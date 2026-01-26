import logging
from pathlib import Path
from fpdf import FPDF

logger = logging.getLogger(__name__)

class CompliancePDF(FPDF):
    def header(self):
        """Formal title at the top of each page."""
        self.set_font("helvetica", "B", 12)
        self.cell(0, 10, "Standard Compliance Check List for Website/Web Applications", ln=True, align="C")
        self.ln(5)

    def footer(self):
        """Standard page numbering footer."""
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()} of {{nb}}", align="R")

    def draw_table_header(self, col_widths):
        """Draws the formal audit table headers with grey fill."""
        self.set_fill_color(230, 230, 230)
        self.set_font("helvetica", "B", 9)
        headers = ["Sr. No.", "Web Security Parameters", "Status", "Remarks"]
        for i, h in enumerate(headers):
            self.cell(col_widths[i], 10, h, border=1, align="C", fill=True)
        self.ln()

    def get_nb_lines(self, width, text):
        """Calculates the number of lines a text will occupy in a multi_cell."""
        if not text:
            return 1
        # Calculate lines based on string width vs column width
        return int(self.get_string_width(text) / width) + 1

def generate_pdf_for_scan(scan, compliance_data, file_prefix="Report", timings=None):
    """
    Generates a formal, color-coded 28-item audit report.
    Includes scan metadata and dynamic box sizing to prevent text overlap.
    """
    pdf = CompliancePDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Metadata Section: Start and End Times
    if timings:
        pdf.set_font("helvetica", "B", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.cell(0, 7, f"Scan Start: {timings.get('start', 'N/A')}", ln=True)
        pdf.cell(0, 7, f"Scan End:   {timings.get('end', 'N/A')}", ln=True)
        pdf.ln(5)
        pdf.set_text_color(0, 0, 0) # Reset to black

    # Precise column widths for A4 (190mm total)
    col_widths = [15, 85, 20, 70] 
    pdf.draw_table_header(col_widths)

    parameters = [
        ("(1)", "Port 80 and 443 are only open"),
        ("(2)", "Website should not be operational over http only"),
        ("(3)", "Website is operational over https only"),
        ("(4)", "Header: Webserver version disclosure disabled"),
        ("(5)", "Header: PHP/CMS/Other software version disclosure"),
        ("(6)", "Header: E-tag leaks sensitive information"),
        ("(7)", "Header: X-XSS-Protection enabled"),
        ("(8)", "Header: X-Frame-Options enabled (Clickjacking)"),
        ("(9)", "Header: HSTS (Strict-Transport-Security) enabled"),
        ("(10)", "Header: Content-Security-Policy (CSP) enabled"),
        ("(11)", "Header: Cookies set as HttpOnly and Secure"),
        ("(12)", "Header: Cookie 'Same-site' attribute set"),
        ("(13)", "Header: Cache-control headers set"),
        ("(14)", "Insecure HTTP Methods (PUT, DELETE, etc.) disabled"),
        ("(15)", "Management/CMS login not accessible over Internet"),
        ("(16)", "TLS 1.0, SSLv2, SSLv3 disabled"),
        ("(17)", "Weak Cipher support disabled"),
        ("(18)", "Protection from POODLE attack"),
        ("(19)", "Protection from Logjam attack"),
        ("(20)", "Protection from Heartbleed bug"),
        ("(21)", "Protection from CRIME vulnerability"),
        ("(22)", "Protection from CCS Injection"),
        ("(23)", "Protection from Anonymous Ciphers"),
        ("(24)", "Protection from FREAK attack"),
        ("(25)", "Protection from DROWN attack"),
        ("(26)", "Support for Forward Secrecy"),
        ("(27)", "Blocking of HTTP/1.0 responses"),
        ("(28)", "DNS CAA record configured")
    ]

    for sr_raw, text in parameters:
        sr_num = sr_raw.strip("()")
        info = compliance_data.get(sr_num, {"status": "Y", "remark": "Compliant.", "severity": "info"})

        # Logic to determine row height to prevent overlapping boxes
        line_height = 6
        nb_lines_param = pdf.get_nb_lines(col_widths[1], text)
        nb_lines_remark = pdf.get_nb_lines(col_widths[3], info["remark"])
        
        # Row height is the maximum lines needed * line height
        row_height = max(nb_lines_param, nb_lines_remark) * line_height
        if row_height < 10: 
            row_height = 10

        # Automatic page break
        if pdf.get_y() + row_height > 270:
            pdf.add_page()
            pdf.draw_table_header(col_widths)

        # Apply severity colors based on scan findings
        sev = info.get("severity", "info").lower()
        if sev in ["critical", "error", "high"]:
            pdf.set_text_color(200, 0, 0)   # Red
        elif sev in ["warning", "medium"]:
            pdf.set_text_color(255, 140, 0) # Orange
        else:
            pdf.set_text_color(0, 128, 0)   # Green

        # Save coordinates for the multi_cell layout
        x_start, y_start = pdf.get_x(), pdf.get_y()

        # Draw the Row (Synchronized Heights)
        pdf.multi_cell(col_widths[0], row_height, sr_raw, border=1, align="C")
        
        pdf.set_xy(x_start + col_widths[0], y_start)
        pdf.multi_cell(col_widths[1], line_height if nb_lines_param > 1 else row_height, text, border=1)
        
        pdf.set_xy(x_start + col_widths[0] + col_widths[1], y_start)
        pdf.multi_cell(col_widths[2], row_height, info["status"], border=1, align="C")
        
        pdf.set_xy(x_start + col_widths[0] + col_widths[1] + col_widths[2], y_start)
        pdf.multi_cell(col_widths[3], line_height if nb_lines_remark > 1 else row_height, info["remark"], border=1)
        
        # Reset color and move cursor to next row
        pdf.set_text_color(0, 0, 0)
        pdf.set_y(y_start + row_height)

    return pdf.output(), f"{file_prefix}.pdf"

def save_pdf_file(pdf_bytes: bytes, filename: str) -> str:
    """Saves the generated PDF to the volume-mapped directory."""
    output_dir = Path("/app/pdf_reports")
    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)
    
    file_path = output_dir / filename
    file_path.write_bytes(pdf_bytes)
    return str(file_path)