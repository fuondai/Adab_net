# Thêm exception handling và logging
def scan_subdomains(domain):
    try:
        with semaphore:
            subdomain = q.get()
            url = f"http://{subdomain}.{domain}"
            
            logger.info(f"Scanning subdomain: {url}")
            response = attempt_request(url)
            
            if response:
                logger.info(f"Found subdomain: {url}")
                with list_lock:
                    discovered_domains.append(url)
            else:
                logger.debug(f"Subdomain not found: {url}")
                
    except Exception as e:
        logger.error(f"Error scanning subdomain {url}: {e}")
        raise
    finally:
        q.task_done() 