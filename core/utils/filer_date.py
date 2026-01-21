from datetime import datetime , timedelta

def get_date_filter(filter_type: str):
    now = datetime.utcnow()

    if filter_type == "daily":
        start = now.replace(hour=0, minute=0, second=0)
    elif filter_type == "weekly":
        start = now - timedelta(days=7)
    elif filter_type == "yearly":
        start = now.replace(month=1, day=1)
    else:  # monthly
        start = now.replace(day=1)

    return start, now
