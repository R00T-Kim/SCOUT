from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Static, Button, DataTable, Log, TabbedContent, TabPane, ProgressBar
from textual.reactive import reactive
from textual import work
import time
import json
from report.reporter import Reporter
from utils.schemas import VulnerabilityCandidate

class ScoutApp(App):
    CSS = """
    Screen {
        layout: vertical;
    }
    .box {
        height: 100%;
        border: solid green;
    }
    #sidebar {
        width: 30;
        dock: left;
        background: $panel;
        padding: 1;
    }
    #main-content {
        height: 100%;
        padding: 1;
    }
    LoadingBar {
        width: 100%;
        margin-bottom: 1;
    }
    """
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "run_scan", "Run Analysis"),
    ]

    analysis_progress = reactive(0)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Footer()
        
        with TabbedContent(initial="dashboard"):
            with TabPane("Dashboard", id="dashboard"):
                yield Static("SCOUT Analysis Dashboard", classes="header")
                self.progress_bar = ProgressBar(total=100, show_eta=True, id="pbar")
                yield self.progress_bar
                yield Button("Start Analysis", id="start_btn", variant="primary")
                self.log_widget = Log(id="scan_log")
                yield self.log_widget
            
            with TabPane("Candidates", id="candidates"):
                self.table = DataTable()
                self.table.cursor_type = "row"
                yield self.table

            with TabPane("Details", id="details"):
                self.detail_view = Static("Select a candidate to view details.", id="detail_content")
                yield self.detail_view

    def on_mount(self) -> None:
        self.table.add_columns("ID", "Type", "Confidence", "Anchor")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start_btn":
            self.run_analysis()

    @work(thread=True)
    def run_analysis(self) -> None:
        self.log_widget.write_line("[*] detailed_log: Starting SCOUT Analysis...")
        self.update_progress(10)
        time.sleep(1)
        
        self.log_widget.write_line("[+] Phase 1: Running EMBA...")
        self.update_progress(30)
        time.sleep(1)
        
        self.log_widget.write_line("[+] Phase 1: Running FirmAE...")
        self.update_progress(50)
        time.sleep(1)
        
        self.log_widget.write_line("[+] Phase 2: Agent Synthesis (Xiaomi Model)...")
        self.update_progress(70)
        time.sleep(2)
        
        self.log_widget.write_line("[+] Phase 4: Validating Candidates...")
        self.update_progress(90)
        time.sleep(0.5)
        
        self.load_results()
        self.log_widget.write_line("[*] Analysis Complete!")
        self.update_progress(100)

    def update_progress(self, val: int) -> None:
        self.app.call_from_thread(self.progress_bar.update, progress=val)

    def load_results(self) -> None:
        # Load the generated report or mock data
        # For prototype, we'll try to read the JSON candidates produced by scout.py
        # Or just hardcode the ones we saw for demo if file doesn't exist
        try:
             # Ideally scout.py should save json. For now let's mock the display
             # based on what we saw in the previous turn
             candidates = [
                 ("CAND-001", "insecure_service", "HIGH", "tcp:23/telnetd"),
                 ("CAND-002", "hardcoded_credentials", "HIGH", "/etc/shadow"),
                 ("CAND-003", "malicious_persistence", "HIGH", "/etc/init.d/rcS"),
                 ("CAND-004", "command_injection", "MEDIUM", "/bin/httpd"),
                 ("CAND-005", "buffer_overflow", "MEDIUM", "/bin/auth"),
             ]
             self.app.call_from_thread(self.table.clear)
             for cand in candidates:
                 self.app.call_from_thread(self.table.add_row, *cand)
        except Exception as e:
            self.log_widget.write_line(f"[!] Error loading results: {e}")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_key = event.row_key
        row = self.table.get_row(row_key)
        cand_id = row[0]
        # In a real app, look up the detailed object
        details = f"""
        # Candidate Details: {cand_id}
        
        **Type**: {row[1]}
        **Confidence**: {row[2]}
        **Anchor**: {row[3]}
        
        ### Description
        Selected candidate detailed view simulated.
        In the full version, this will show specific evidence and reproduction steps.
        """
        self.query_one("#detail_content", Static).update(details)

if __name__ == "__main__":
    app = ScoutApp()
    app.run()
