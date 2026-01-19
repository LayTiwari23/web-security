from celery import shared_task

@shared_task(name="generate_pdf_report")
def generate_pdf_report_task(scan_id: int, user_id: int):
    print(f"Generating report for scan {scan_id}")
    return True