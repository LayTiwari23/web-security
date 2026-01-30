import logging
from pathlib import Path
from fpdf import FPDF

logger = logging.getLogger(__name__)

class CompliancePDF(FPDF):
    def header(self):
        """Formal title at the top of each page."""
        if self.page_no() == 1:
            self.set_font("helvetica", "B", 14)
            self.cell(0, 10, "Security Compliance Audit Report", ln=True, align="C")
            self.set_font("helvetica", "B", 11)
            self.cell(0, 10, "Standard Compliance Check List for Web Applications", ln=True, align="C")
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
        # Clean text to handle encoding issues
        text = str(text).encode('latin-1', 'replace').decode('latin-1')
        cw = self.current_font['cw']
        if width == 0:
            width = self.w - self.r_margin - self.x
        wmax = (width - 2 * self.c_margin) * 1000 / self.font_size
        s = text.replace('\r', '')
        nb = len(s)
        if nb > 0 and s[nb - 1] == '\n':
            nb -= 1
        sep = -1
        i = 0
        j = 0
        l = 0
        nl = 1
        while i < nb:
            c = s[i]
            if c == '\n':
                i += 1
                sep = -1
                j = i
                l = 0
                nl += 1
                continue
            if c == ' ':
                sep = i
            l += cw.get(c, 0)
            if l > wmax:
                if sep == -1:
                    if i == j:
                        i += 1
                else:
                    i = sep + 1
                sep = -1
                j = i
                l = 0
                nl += 1
            else:
                i += 1
        return nl

def generate_pdf_for_scan(scan, compliance_data, file_prefix="Report", timings=None):
    """
    Generates a formal, color-coded 28-item audit report.
    """
    pdf = CompliancePDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Metadata Section
    pdf.set_font("helvetica", "B", 10)
    pdf.set_fill_color(245, 245, 245)
    pdf.cell(0, 8, f" Target URL: {scan.target.url}", ln=True, border='TLR', fill=True)
    if timings:
        pdf.cell(0, 8, f" Scan Period: {timings.get('start')} to {timings.get('end')}", ln=True, border='BLR', fill=True)
    pdf.ln(5)

    col_widths = [15, 80, 20, 75] 
    pdf.draw_table_header(col_widths)

    parameters = [
        ("(1)", "Port 80 and 443 are only open"),
        ("(2)", "Website should not be operational over HTTP only"),
        ("(3)", "Website is operational over HTTPS only"),
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

    pdf.set_font("helvetica", "", 9)
    
    for sr_raw, text in parameters:
        sr_num = sr_raw.strip("()")
        info = compliance_data.get(sr_num, {"status": "Y", "remark": "Compliant.", "severity": "info"})
        
        # Calculate row height
        line_height = 5
        nb_lines_param = pdf.get_nb_lines(col_widths[1], text)
        nb_lines_remark = pdf.get_nb_lines(col_widths[3], info["remark"])
        row_height = max(nb_lines_param, nb_lines_remark) * line_height
        if row_height < 8: row_height = 8

        # Page break check
        if pdf.get_y() + row_height > 270:
            pdf.add_page()
            pdf.draw_table_header(col_widths)
            pdf.set_font("helvetica", "", 9)

        # Set Colors
        sev = info.get("severity", "info").lower()
        if info["status"] == "N" or sev in ["critical", "error", "high"]:
            pdf.set_text_color(180, 0, 0)
        elif sev in ["warning", "medium"]:
            pdf.set_text_color(210, 105, 30)
        else:
            pdf.set_text_color(0, 100, 0)

        # Draw Cells
        x, y = pdf.get_x(), pdf.get_y()
        pdf.multi_cell(col_widths[0], row_height, sr_raw, border=1, align="C")
        
        pdf.set_xy(x + col_widths[0], y)
        pdf.multi_cell(col_widths[1], row_height / nb_lines_param, text, border=1, align="L")
        
        pdf.set_xy(x + col_widths[0] + col_widths[1], y)
        pdf.multi_cell(col_widths[2], row_height, info["status"], border=1, align="C")
        
        pdf.set_xy(x + col_widths[0] + col_widths[1] + col_widths[2], y)
        pdf.multi_cell(col_widths[3], row_height / nb_lines_remark, info["remark"], border=1, align="L")
        
        pdf.set_text_color(0, 0, 0)
        pdf.set_y(y + row_height)

    return pdf.output(), f"{file_prefix}.pdf"

def save_pdf_file(pdf_bytes: bytes, filename: str) -> str:
    output_dir = Path("/app/pdf_reports")
    output_dir.mkdir(parents=True, exist_ok=True)
    file_path = output_dir / filename
    file_path.write_bytes(pdf_bytes)
    return str(file_path)