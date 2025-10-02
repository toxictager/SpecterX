from tqdm import tqdm
import time

def with_progress(iterable, desc="Progress", delay=0, total=None):
    if total is None:
        try:
            total = len(iterable)
        except (TypeError, AttributeError):
            total = None

    bar = tqdm(iterable, desc=desc, total=total, ncols=80)
    for item in bar:
        yield item
        if delay:
            time.sleep(delay)
