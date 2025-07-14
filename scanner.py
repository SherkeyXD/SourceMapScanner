import argparse
import asyncio
import json
import logging
import re
import shutil
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urljoin, urlparse

import nest_asyncio
from playwright.async_api import async_playwright, Error as PlaywrightError
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

nest_asyncio.apply()


@dataclass
class ScanResult:
    js_url: str
    map_url: str
    detection_method: str
    response_size: Optional[int] = None
    content_type: Optional[str] = None
    timestamp: Optional[str] = None


@dataclass
class ScanSummary:
    target_url: str
    total_js_files: int
    vulnerabilities_found: int
    scan_duration: float
    timestamp: str
    vulnerabilities: List[ScanResult]


class SourceMapScannerPro:
    def __init__(self, base_url: str, config: Dict[str, Any], url_index: Optional[int] = None):
        self.base_url = self._format_base_url(base_url)
        self.config = config
        self.url_index = url_index
        self.timeout = config.get("timeout", 15) * 1000
        self.js_files: Set[str] = set()
        self.vulnerabilities: List[ScanResult] = []
        self.console = Console()
        self.logger = self._setup_logging()
        self.api_context = None
        self.start_time = None

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO if self.config.get("verbose") else logging.WARNING)

        if not logger.handlers:
            handler = RichHandler(
                rich_tracebacks=True, 
                console=self.console,
                show_path=False,
                show_time=False
            )
            formatter = logging.Formatter("%(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _format_base_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def _get_domain(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc.lower()

    def _is_same_domain(self, url: str) -> bool:
        base_domain = self._get_domain(self.base_url)
        url_domain = self._get_domain(url)
        return base_domain == url_domain

    async def _validate_source_map(self, map_url: str) -> bool:
        if not self.config.get("strict", False):
            return True
            
        if not self.api_context:
            self.logger.debug("API context not available for source map validation")
            return False
            
        try:
            response = await self.api_context.get(map_url)
            if not response.ok:
                return False
                
            content = await response.text()
            
            map_data = json.loads(content)
            
            required_fields = ["version", "sources"]
            for field in required_fields:
                if field not in map_data:
                    self.logger.debug(f"Source map validation failed: missing {field} in {map_url}")
                    return False
                    
            if map_data.get("version") != 3:
                self.logger.debug(f"Source map validation failed: unsupported version {map_data.get('version')} in {map_url}")
                return False
                
            return True
            
        except json.JSONDecodeError:
            self.logger.debug(f"Source map validation failed: invalid JSON in {map_url}")
            return False
        except Exception as e:
            self.logger.debug(f"Source map validation error for {map_url}: {e}")
            return False

    async def _get_js_with_playwright(self, p) -> bool:
        self.console.print(
            "[bold cyan]🚀 Launching browser to discover JavaScript files...[/bold cyan]"
        )

        js_files_found = set()
        browser = None

        def on_request(request):
            if request.resource_type == "script" and self._is_same_domain(request.url):
                js_files_found.add(request.url)
                self.logger.info(f"Discovered JS file: {request.url}")

        def on_response(response):
            if (response.url.endswith(".js") or "javascript" in response.headers.get(
                "content-type", ""
            )) and self._is_same_domain(response.url):
                js_files_found.add(response.url)

        try:
            browsers_to_try = ["firefox", "chromium", "webkit"]
            browser_launched = False

            for browser_name in browsers_to_try:
                try:
                    browser = await getattr(p, browser_name).launch(
                        headless=self.config.get("show_browser", False)
                    )
                    browser_launched = True
                    self.logger.info(f"Successfully launched {browser_name}")
                    break
                except Exception as e:
                    self.logger.warning(f"Failed to launch {browser_name}: {e}")
                    continue

            if not browser_launched or browser is None:
                self.console.print(
                    "[bold red]❌ Failed to launch any browser[/bold red]"
                )
                return False

            page = await browser.new_page()
            page.on("request", on_request)
            page.on("response", on_response)

            await page.set_extra_http_headers(
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
            )

            self.console.print(f"[cyan]🌐 Navigating to {self.base_url}[/cyan]")

            await page.goto(
                self.base_url, wait_until="networkidle", timeout=self.timeout
            )

            await asyncio.sleep(3)

            additional_scripts = await page.evaluate(
                """
                () => {
                    const scripts = Array.from(document.querySelectorAll('script[src]'));
                    return scripts.map(script => script.src).filter(src => src);
                }
            """
            )

            for script_url in additional_scripts:
                if script_url.startswith("http"):
                    if self._is_same_domain(script_url):
                        js_files_found.add(script_url)
                elif script_url.startswith("/"):
                    full_url = urljoin(self.base_url, script_url)
                    if self._is_same_domain(full_url):
                        js_files_found.add(full_url)

            await browser.close()

            self.js_files.update(js_files_found)
            
            self.js_files = {url for url in self.js_files if self._is_same_domain(url)}
            
            self.console.print(
                f"[bold green]✅ Browser session completed. Found {len(self.js_files)} unique JS files from current domain[/bold green]\n"
            )

            return True

        except PlaywrightError as e:
            self.console.print(f"[bold red]❌ Browser navigation error: {e}[/bold red]")
            return False
        except Exception as e:
            self.console.print(f"[bold red]❌ Unexpected error: {e}[/bold red]")
            return False
        finally:
            if browser:
                try:
                    await browser.close()
                except Exception:
                    pass

    async def _check_sourcemap(
        self, js_url: str, progress: Progress, task_id
    ) -> Optional[ScanResult]:
        if not self.api_context:
            self.logger.error("API context not initialized")
            return None

        map_url_found = None
        detection_method = None
        response_size = None
        content_type = None

        try:
            js_response = await self.api_context.get(js_url)
            if js_response.ok:
                content = await js_response.text()
                response_size = len(content)
                content_type = js_response.headers.get("content-type", "")

                patterns = [
                    r"//[#@]\s*sourceMappingURL=([^\s\r\n]+)",
                    r"/\*[#@]\s*sourceMappingURL=([^\s\r\n]+)\s*\*/",
                ]

                for pattern in patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        map_path = matches[-1].strip()
                        if not map_path.startswith("data:"):
                            map_url = urljoin(js_url, map_path)
                            map_response = await self.api_context.head(map_url)
                            if map_response.ok and await self._validate_source_map(map_url):
                                map_url_found = map_url
                                detection_method = "sourceMappingURL comment"
                                break

            if not map_url_found:
                potential_map_url = js_url + ".map"
                map_response = await self.api_context.head(potential_map_url)
                if map_response.ok and await self._validate_source_map(potential_map_url):
                    map_url_found = potential_map_url
                    detection_method = ".map suffix"

            if not map_url_found and self.config.get("deep_scan", False):
                base_name = js_url.rsplit("/", 1)[-1]
                if base_name.endswith(".js"):
                    base_name = base_name[:-3]

                map_patterns = [
                    f"{base_name}.js.map",
                    f"{base_name}.min.js.map",
                    f"maps/{base_name}.js.map",
                    f"sourcemaps/{base_name}.js.map",
                ]

                base_url = js_url.rsplit("/", 1)[0]
                for pattern in map_patterns:
                    test_url = f"{base_url}/{pattern}"
                    map_response = await self.api_context.head(test_url)
                    if map_response.ok and await self._validate_source_map(test_url):
                        map_url_found = test_url
                        detection_method = f"pattern: {pattern}"
                        break

        except Exception as e:
            self.logger.debug(f"Error checking {js_url}: {e}")

        if map_url_found and detection_method:
            result = ScanResult(
                js_url=js_url,
                map_url=map_url_found,
                detection_method=detection_method,
                response_size=response_size,
                content_type=content_type,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            )
            self.vulnerabilities.append(result)
            progress.update(
                task_id,
                description=f"[bold yellow]🎯 Found![/bold yellow] {js_url[:50]}...",
            )
            return result
        else:
            progress.update(task_id, description=f"[dim]✓ {js_url[:70]}...[/dim]")

        progress.advance(task_id)
        return None

    async def scan(self) -> ScanSummary:
        self.start_time = time.time()

        self.console.print(
            Panel(
                f"[bold]Target:[/bold] {self.base_url}\n[bold]Domain:[/bold] {self._get_domain(self.base_url)}\n[bold]Timeout:[/bold] {self.config['timeout']}s",
                title="🔍 Source Map Scanner",
                border_style="blue",
            )
        )

        async with async_playwright() as p:
            if not await self._get_js_with_playwright(p):
                return self._create_summary()

            if not self.js_files:
                self.console.print(
                    "[yellow]⚠️ No JavaScript files found on the target page[/yellow]"
                )
                return self._create_summary()

            self.api_context = await p.request.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                ignore_https_errors=True,
                timeout=self.timeout,
            )

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=self.console,
                transient=True,
            ) as progress:
                task_id = progress.add_task(
                    "[cyan]🔍 Scanning for source maps...", total=len(self.js_files)
                )

                semaphore = asyncio.Semaphore(self.config.get("max_concurrent", 10))

                async def check_with_semaphore(js_url):
                    async with semaphore:
                        return await self._check_sourcemap(js_url, progress, task_id)

                tasks = [check_with_semaphore(js_url) for js_url in self.js_files]
                await asyncio.gather(*tasks, return_exceptions=True)

            if self.config.get("download_dir") and self.vulnerabilities:
                await self._download_vulnerabilities(self.config["download_dir"])

            await self.api_context.dispose()

        summary = self._create_summary()
        self._print_report(summary)
        self._save_results(summary)

        return summary

    def _create_summary(self) -> ScanSummary:
        duration = time.time() - self.start_time if self.start_time else 0
        return ScanSummary(
            target_url=self.base_url,
            total_js_files=len(self.js_files),
            vulnerabilities_found=len(self.vulnerabilities),
            scan_duration=duration,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            vulnerabilities=self.vulnerabilities,
        )

    def _print_report(self, summary: ScanSummary):
        self.console.print("\n[bold]📊 Scan Report[/bold]", justify="center")

        summary_table = Table(show_header=False, box=None)
        summary_table.add_row("🎯 Target", summary.target_url)
        summary_table.add_row("🌐 Domain", self._get_domain(summary.target_url))
        summary_table.add_row("📁 JS Files Found", str(summary.total_js_files))
        summary_table.add_row("🚨 Vulnerabilities", str(summary.vulnerabilities_found))
        summary_table.add_row("⏱️ Scan Duration", f"{summary.scan_duration:.2f}s")
        summary_table.add_row("📅 Timestamp", summary.timestamp)

        if not self.vulnerabilities:
            success_panel = Panel(
                summary_table,
                title="[green]✅ No Source Map Leakage Detected[/green]",
                border_style="green",
            )
            self.console.print(success_panel)
        else:
            vuln_table = Table(
                title=f"🚨 {len(self.vulnerabilities)} Source Map Vulnerabilities Found",
                show_header=True,
                header_style="bold magenta",
            )
            vuln_table.add_column("No.", style="dim", width=4)
            vuln_table.add_column("JavaScript File", style="cyan", no_wrap=False)
            vuln_table.add_column("Source Map URL", style="yellow", no_wrap=False)
            vuln_table.add_column("Detection Method", style="green", no_wrap=True)

            for i, vuln in enumerate(self.vulnerabilities, 1):
                vuln_table.add_row(
                    str(i), vuln.js_url, vuln.map_url, vuln.detection_method
                )

            warning_panel = Panel(
                vuln_table,
                title="[red]⚠️ Vulnerability Found[/red]",
                border_style="red",
            )
            self.console.print(warning_panel)

        self.console.print(f"\n[dim]Scan completed in {summary.scan_duration:.2f}s at {summary.timestamp}[/dim]")

    def _save_results(self, summary: ScanSummary):
        if not self.config.get("download_dir"):
            return

        base_download_path = Path(self.config["download_dir"])
        
        if self.url_index is not None:
            domain = self._get_domain(self.base_url)
            safe_domain = "".join(c if c.isalnum() or c in '-_.' else '_' for c in domain)
            download_path = base_download_path / f"{self.url_index:03d}_{safe_domain}"
        else:
            download_path = base_download_path
            
        download_path.mkdir(parents=True, exist_ok=True)
        output_file = download_path / "results.json"
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(asdict(summary), f, indent=2, ensure_ascii=False)
        self.console.print(f"[green]💾 Results saved to {output_file}[/green]")

    def _sanitize_filename(self, url: str) -> str:
        parsed = urlparse(url)
        path = parsed.path
        if path.endswith('/'):
            filename = 'index.js'
        else:
            filename = Path(path).name or 'unknown'
        
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        
        return filename

    async def _download_file(self, url: str, download_dir: Path, filename: Optional[str] = None) -> Optional[str]:
        if not self.api_context:
            self.logger.error("API context not available for download")
            return None
            
        try:
            if not filename:
                filename = self._sanitize_filename(url)
            
            file_path = download_dir / filename
            counter = 1
            original_stem = file_path.stem
            original_suffix = file_path.suffix
            
            while file_path.exists():
                new_name = f"{original_stem}_{counter}{original_suffix}"
                file_path = download_dir / new_name
                counter += 1
            
            response = await self.api_context.get(url)
            if response.ok:
                content = await response.body()
                
                with open(file_path, 'wb') as f:
                    f.write(content)
                
                self.logger.info(f"Downloaded: {url} -> {file_path}")
                return str(file_path)
            else:
                self.logger.warning(f"Failed to download {url}: HTTP {response.status}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error downloading {url}: {e}")
            return None

    async def _download_vulnerabilities(self, download_dir: str):
        if not self.vulnerabilities:
            return
        
        base_download_path = Path(download_dir)
        
        if self.url_index is not None:
            domain = self._get_domain(self.base_url)
            safe_domain = "".join(c if c.isalnum() or c in '-_.' else '_' for c in domain)
            download_path = base_download_path / f"{self.url_index:03d}_{safe_domain}"
        else:
            download_path = base_download_path
        
        if download_path.exists():
            self.console.print(f"[yellow]🗑️ Clearing existing files in download directory: {download_path}[/yellow]")
            for item in download_path.iterdir():
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
        else:
            download_path.mkdir(parents=True, exist_ok=True)
        
        self.console.print(f"\n[bold cyan]📥 Downloading vulnerable files to: {download_path}[/bold cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        ) as progress:
            total_files = len(self.vulnerabilities) * 2
            task_id = progress.add_task("[cyan]Downloading files...", total=total_files)
            
            download_log = []
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                js_filename = self._sanitize_filename(vuln.js_url)
                base_name = Path(js_filename).stem
                
                file_dir = download_path / base_name
                file_dir.mkdir(exist_ok=True)
                
                progress.update(task_id, description=f"[cyan]Downloading JS file {i}/{len(self.vulnerabilities)}...")
                js_path = await self._download_file(vuln.js_url, file_dir, js_filename)
                progress.advance(task_id)
                
                progress.update(task_id, description=f"[yellow]Downloading map file {i}/{len(self.vulnerabilities)}...")
                map_filename = self._sanitize_filename(vuln.map_url)
                map_path = await self._download_file(vuln.map_url, file_dir, map_filename)
                progress.advance(task_id)
                
                download_log.append({
                    'index': i,
                    'js_url': vuln.js_url,
                    'map_url': vuln.map_url,
                    'js_file': js_path,
                    'map_file': map_path,
                    'detection_method': vuln.detection_method,
                    'folder': str(file_dir)
                })
        
        success_count = sum(1 for log in download_log if log['js_file'] and log['map_file'])
        self.console.print(f"[bold green]✅ Download completed! {success_count}/{len(self.vulnerabilities)} pairs downloaded successfully[/bold green]")
        self.console.print(f"[dim]Files saved to: {download_path}[/dim]")


def main():
    parser = argparse.ArgumentParser(
        description="🔍 Source Map Scanner - Advanced vulnerability scanner for source map leakages (scans current domain only)",
        epilog="Example: python scanner.py -u https://example.com -v -d ./downloads --strict",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    url_group = parser.add_mutually_exclusive_group(required=True)
    url_group.add_argument(
        "-u", "--url", 
        type=str, 
        help="Target website URL to scan"
    )
    url_group.add_argument(
        "-f", "--file", 
        type=str, 
        help="File containing URLs to scan (one URL per line)"
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=15,
        help="Request timeout in seconds (default: 15)",
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true", 
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--deep-scan",
        action="store_true",
        help="Enable deep scan with additional detection patterns",
    )
    parser.add_argument(
        "-c", "--max-concurrent",
        type=int,
        default=10,
        help="Maximum concurrent requests (default: 10)",
    )
    parser.add_argument(
        "-b", "--show-browser",
        action="store_false",
        dest="show_browser",
        help="Don't run browser in headless mode (use this flag to show browser)",
    )
    parser.add_argument(
        "-d", "--download",
        type=str,
        metavar="DIR",
        help="Download vulnerable JS and source map files to specified directory",
    )
    parser.add_argument(
        "-s", "--strict",
        action="store_true",
        help="Strict mode: validate source map files have proper JSON structure",
    )

    args = parser.parse_args()

    urls = []
    if args.url:
        urls = [args.url]
    elif args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            if not urls:
                print("❌ No valid URLs found in file")
                sys.exit(1)
        except FileNotFoundError:
            print(f"❌ File not found: {args.file}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            sys.exit(1)

    config = {
        "timeout": args.timeout,
        "verbose": args.verbose,
        "deep_scan": args.deep_scan,
        "max_concurrent": args.max_concurrent,
        "show_browser": args.show_browser,
        "download_dir": args.download,
        "strict": args.strict,
    }

    try:
        total_vulnerabilities = 0
        
        for i, url in enumerate(urls, 1):
            if len(urls) > 1:
                print(f"\n{'='*60}")
                print(f"🔍 Scanning {i}/{len(urls)}: {url}")
                print('='*60)
            
            url_index = i if len(urls) > 1 else None
            scanner = SourceMapScannerPro(url, config, url_index)
            summary = asyncio.run(scanner.scan())
            total_vulnerabilities += summary.vulnerabilities_found
            
            if len(urls) > 1:
                print(f"✅ Scan {i} completed: {summary.vulnerabilities_found} vulnerabilities found")

        if len(urls) > 1:
            print(f"\n🎯 Total scans: {len(urls)}")
            print(f"🚨 Total vulnerabilities: {total_vulnerabilities}")

        sys.exit(0 if total_vulnerabilities == 0 else 1)

    except KeyboardInterrupt:
        print("\n🛑 Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
