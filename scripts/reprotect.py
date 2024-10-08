#!/usr/bin/env python3

"""
Protection Helper Bot - reprotect.py

This script retrieves and processes protection logs from a MediaWiki site to manage and restore
protection settings. It's designed to be run under supervisord or a similar process manager.

Functionality:
- Monitor the protection log for temporary higher protection levels and their expirations.
- After expiration, check the page protection status and restore the previous protection if needed.
- Log protection changes with the appropriate reason and attribution.

No reprotection action is taken in the following cases:
- The duration of the higher protection level extends beyond the prior protection's expiration.
- The expiring protection level is not higher than the previous protection level.
- There is a more recent protection action.
- Any of the most recent actions is a cascading protection.
- A serious error occurs during the restoration process.
- The restored protection would be shorter than MINIMUM_DURATION (default: 1 day).

Non-standard dependencies:
- pywikibot: For interacting with MediaWiki.
"""

import argparse
import logging
import os
import pywikibot
import random
import re
import sys
import time
import traceback

from datetime import datetime, timedelta


# configuration
LOOKBACK_INTERVAL = timedelta(days=731) # log period to review
RECENT_INTERVAL = timedelta(days=90) # act on protections that have expired within this period
MINIMUM_DURATION = timedelta(days=1) # minimum duration required for reprotection
DRY_RUN = os.getenv('REPROTECT_DRY_RUN', 'true').lower() != 'false' # no actions by default


# timezone and logging
os.environ['TZ'] = 'UTC'
time.tzset()
logging.basicConfig(format='%(asctime)s | %(levelname)s | %(funcName)s | %(message)s',
                    datefmt='%Y-%m-%dT%H:%M:%S',
                    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper(), logging.INFO))


def parse_args():
    """
    Parse command-line arguments for the Protection Manager script.

    Returns:
    namespace (argparse.Namespace): Parsed arguments, including --backtest and --future options.
    """
    parser = argparse.ArgumentParser(description="Protection Manager Script")
    parser.add_argument('--backtest', action='store_true', help="Simulate past protection expirations, ignoring newer actions (testing only)")
    parser.add_argument('--future', type=int, default=0, help="Simulate protections for a specified number of future days (testing only)")

    # not suitable for running in production
    args = parser.parse_args()
    if args.backtest or args.future:
        assert DRY_RUN, "command line options should only be used in dry runs"

    return args


def login():
    """
    Authenticate on the MediaWiki site and return the site object.

    Returns:
    site (pywikibot.Site): The MediaWiki site to monitor.
    """
    site = pywikibot.Site()
    site.login()
    if site.userinfo['name'] == site.username():
        logging.info(f"successfully logged in as {site.username()}")
        return site
    else:
        logging.error("login failed")
        time.sleep(300)
        sys.exit(1)


class RateLimit:
    """
    Rate limit actions to ensure a minimum delay between actions.
    """

    def __init__(self, delay: timedelta):
        """
        Initialize rate limiter.

        Parameters:
        delay (timedelta): Minimum time between actions.
        """
        self.delay = delay
        self.last = datetime.now() - self.delay

    def throttle(self):
        """
        Enforce the rate limit by sleeping if necessary.
        """
        elapsed_time = datetime.now() - self.last
        sleep_time = max(0, (self.delay - elapsed_time).total_seconds())
        if sleep_time > 0:
            time.sleep(sleep_time)
        self.last = datetime.now()


class ProtectionFunctions:
    """
    Utility class for general functions used across protection-related classes.
    """
    levels = {'autoconfirmed': 0, 'extendedconfirmed': 1, 'templateeditor': 2, 'sysop': 3}

    @staticmethod
    def iso_to_timestamp(iso_string):
        """
        Convert an ISO 8601 date-time string to a UNIX timestamp.

        Parameters:
        iso_string (str): The ISO 8601 date-time string (e.g., '2025-03-02T05:30:26Z').

        Returns:
        float: The corresponding UNIX timestamp.
        """
        # Parse the ISO 8601 string into a datetime object
        dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
        # Convert the datetime object to a UNIX timestamp
        return dt.timestamp()


    @staticmethod
    def protection_level(level):
        """
        Map a protection level name to its integer representation.

        Parameters:
        level (str): The protection level name (e.g., 'autoconfirmed').

        Returns:
        int: The integer representation of the protection level.

        Notes:
        Verified for English Wikipedia only.
        """
        return ProtectionFunctions.levels.get(level, -1)


class ProtectionLogs:
    """
    Class to handle retrieval and parsing of protection logs from a MediaWiki site.
    """

    def __init__(self, site):
        """
        Initialize the ProtectionLogs instance.

        Parameters:
        site (pywikibot.Site): The site from which to retrieve logs.
        """
        self.site = site
        self.position = datetime.now() - LOOKBACK_INTERVAL
        self.queries = 0

    def fetch_all_logs(self):
        """
        Retrieve all protection logs within the configured date range.

        Yields:
        tuple: A tuple containing log data and details.
        """
        start = self.position
        end = datetime.now()
        self.position = end
        logging.info(f"query {start} to {end}")
        for log in self.site.logevents(logtype='protect', start=start, end=end, reverse=True):
            if log_result := self.parse_log(log):
                yield log_result
        self.queries += 1
        return

    def fetch_page_logs(self, page=None, before=None):
        """
        Retrieve protection logs for a specific page.

        Parameters:
        page (str, optional): The page title to retrieve logs for.
        before (int, optional): Only retrieve logs with IDs less than this value.

        Yields:
        tuple: A tuple containing log data and details.
        """
        for log in self.site.logevents(logtype='protect', page=page):
            log_result = self.parse_log(log)

            # skip if not validated
            if not log_result:
                continue
            log_data, details = log_result

            # check logid and only yield if it's less than before
            if before is not None and log_data['logid'] >= before:
                continue  # skip log entries with a logid greater than or equal to the current one
            if log_data['action'] == 'move_prot':
                # switch to the old title and yield logs for it
                logging.debug(f"switching to old title: {details}")
                yield from self.fetch_page_logs(page=details, before=log_data['logid'])
            else:
                yield log_result

    def is_log_data_valid(self, log_data):
        """
        Validate the structure and types of log data.

        Parameters:
        log_data (dict): The log data to validate.

        Returns:
        bool: True if all checks pass, False otherwise.
        """
        required_keys = {
            'logid': int,
            'title': str,
            'action': str,
            'params': dict,
            'user': str,
            'comment': str,
            'timestamp': str
        }

        # check for missing or incorrect type for required keys
        for key, expected_type in required_keys.items():
            if key not in log_data:
                logging.error(f"missing {key} in log data: {log_data}")
                return False
            if not isinstance(log_data[key], expected_type):
                logging.error(f"incorrect type for {key} in log data: expected {expected_type}, got {type(log_data[key])}: {log_data}")
                return False

        return True

    def extract_legacy_protection_details(self, description):
        """
        Extracts details from a legacy protection description.

        Parameters:
        description (str): The protection description text to parse.

        Returns:
        list: A list of dictionaries containing extracted details, where each dictionary includes:
            - 'type': The type of protection.
            - 'level': The protection level.
            - 'expiry': The expiry timestamp of the protection or float('inf') for indefinite.
        None: If no details could be extracted.
        """
        level_map = {
            'Block new and unregistered users': 'autoconfirmed',
            'Block all non-admin users': 'sysop'
        }
        patterns = [
            r'\[(?P<type>create|edit|move|upload)=(?P<level>\w+)\] \((?P<expiry>expires[^\)]+\(UTC\)|indefinite)\)',
            r'\[(?P<type>create)=(?P<level>\w+)\] {2}\((?P<expiry>expires[^\)]+\(UTC\)|indefinite)\)',
            r'\[(?P<type>Create|Edit|Move|Upload)=(?P<level>Block new and unregistered users|Block all non-admin users)\] \((?P<expiry>expires[^\)]+\(UTC\)|indefinite)\)'
        ]
        date_formats = [
            'expires %H:%M, %d %B %Y (UTC)',
            'expires %H:%M, %B %d, %Y (UTC)',
            'expires %Y-%m-%dT%H:%M:%S (UTC)',
            'expires %H:%M, %Y %B %d (UTC)'
        ]
        details = []

        for pattern in patterns:
            for match in re.finditer(pattern, description):
                expiry = match.group('expiry')
                if expiry == 'indefinite':
                    expiry = float('inf')
                else:
                    type_of_protection = match.group('type').lower()
                    max_date_formats = 4 if type_of_protection == 'create' else 1
                    for i in range(max_date_formats):
                        try:
                            expiry = datetime.strptime(expiry, date_formats[i]).timestamp()
                            break
                        except ValueError:
                            continue
                    else:
                        logging.error(f"error parsing expiry date: {description}")
                        return None

                level = match.group('level')
                if level in level_map:
                    level = level_map[level]
                if ProtectionFunctions.protection_level(level) == -1:
                    continue

                details.append({
                    'type': match.group('type').lower(),
                    'level': level,
                    'expiry': expiry
                })

            if details:
                return details

        return None

    def parse_log(self, log):
        """
        Process a log entry to extract and validate its details.

        Parameters:
        log (object): The log entry, expected to have a 'data' attribute.

        Returns:
        tuple: (log_data, details) if the log is valid.
        None: If the log is malformed, incomplete, or cannot be processed.

        Handles various log actions including 'unprotect', 'protect', and 'move_prot'. 
        Supports parsing different log formats and logs errors for malformed or incomplete logs.
        """
        try:
            # skip malformed or incomplete log entries
            log_data = getattr(log, 'data', None)
            if not log_data:
                logging.error(f"no data in log: {vars(log)}")
                return None
            if any(field in log_data for field in ['actionhidden', 'commenthidden', 'suppressed', 'userhidden']):
                logging.debug(f"hidden log: {vars(log)}")
                return None
            # validate log_data
            if not self.is_log_data_valid(log_data):
                return None
        except Exception as e:
            logging.error(f"error processing log: {e}")
            return None

        # any unprotection
        action = log_data['action']
        if action == 'unprotect':
            return log_data, None

        # check details and parse expiry
        params = log_data.get('params', None)
        if not params:
            # ancient log format, only parse if indefinite (2005-12-22 to 2008-12-25)
            if action == 'protect' and isinstance(params, dict):
                comment = log_data.get('comment', '')
                m = re.search(r'(?:^| )\[(edit|move)=(\w+)\]$|(?:^| )\[edit=(\w+):move=(\w+)\]$', comment)
                if m:
                    if m.group(1):
                        details = [
                            {'type': m.group(1), 'level': m.group(2), 'expiry': float('inf')}
                        ]
                    else:
                        details = [
                            {'type': 'edit', 'level': m.group(3), 'expiry': float('inf')},
                            {'type': 'move', 'level': m.group(4), 'expiry': float('inf')}
                        ]
                    logging.info(f"parsed ancient log: {details} | {vars(log)}")
                    return log_data, details
            logging.info(f"missing params: {vars(log)}")
            return None

        # moved protection settings
        if action == 'move_prot':
            oldtitle_title = params.get('oldtitle_title', None)
            if oldtitle_title:
                return log_data, oldtitle_title
            logging.error(f"move_prot missing oldtitle_title: {vars(log)}")
            return None

        # legacy log formats (2008-09-20 to 2015-10-01)
        details = params.get('details', None)
        if not details:
            try:
                description = params.get('description', None)
                if description:
                    extracted_details = self.extract_legacy_protection_details(description)
                    if extracted_details:
                        logging.info(f"parsed legacy log: {log_data['logid']} | {log_data['title']} | {extracted_details} | {vars(log)}")
                        return log_data, extracted_details
            except Exception as e:
                logging.error(f"error parsing legacy log: {e} | {vars(log)}")
                return None

        # log details are missing or improperly formatted
        if not isinstance(details, list):
            logging.warning(f"missing log details: {vars(log)}")
            return None

        # recent protection (after 2015-10-01)
        for detail in details:
            detail_type = detail.get('type', None)
            detail_level = detail.get('level', None)
            detail_expiry = detail.get('expiry', None)

            if not detail_type or not detail_level or not detail_expiry:
                logging.error(f"incomplete log details: {vars(log)}")
                return None

            # get the expiration string and convert it
            if detail_expiry == 'infinite':
                detail['expiry'] = float('inf')
            else:
                try:
                    detail['expiry'] = ProtectionFunctions.iso_to_timestamp(detail_expiry)
                except Exception as e:
                    logging.error(f"error parsing expiry for {vars(log)}: {e}")
                    return None

        return log_data, details


class ProtectionManager:
    """
    Class to manage and restore protection settings based on logs.
    """

    def __init__(self, site, backtest=False, future_days=0):
        """
        Initialize the ProtectionManager instance.

        Parameters:
        site (pywikibot.Site): The site on which to manage protections.
        """
        self.site = site
        self.backtest = backtest
        self.backtest_time = None
        self.future_seconds = timedelta(days=future_days).total_seconds()
        self.logs = ProtectionLogs(site)
        self.protect_rate_limit = RateLimit(timedelta(minutes=60))
        self.update_rate_limit = RateLimit(timedelta(minutes=5))
        self.page_protections = {}

    def update_page_protections(self):
        """
        Process all protection logs and update the internal list of pages with active protections.

        This method processes each log entry, handles unprotection, move protection, and updates
        the list of pages with active protections based on their expiration timestamps.
        """
        # rate limit queries
        self.update_rate_limit.throttle()

        # update page protections
        count = 0
        for log, details in self.logs.fetch_all_logs():
            count += 1
            title = log['title']

            # backtests
            if self.backtest:
                # simulated current time
                self.backtest_time = ProtectionFunctions.iso_to_timestamp(log['timestamp'])
                # process all available expirations
                while expired := manager.find_next_expired_protection():
                    manager.evaluate_protection_restoration(expired)

            # unprotection
            if log['action'] == 'unprotect':
                if title in self.page_protections:
                    logging.debug(f"unprotect action on {title}")
                self.page_protections.pop(title, None)
                continue

            # moved protection settings (details is the old title)
            if log['action'] == 'move_prot':
                if details in self.page_protections:
                    logging.debug(f"moved protection from {details} to {title}: {self.page_protections.get(details)}")
                    self.page_protections[title] = self.page_protections.pop(details)
                continue

            # protection
            try:
                # reasons to exclude an entire log entry from processing
                log_exclusions = set()
                # expirations to track
                filtered_details = []

                # process each protection in the log entry
                for detail in details:
                    # completely skip if there's an unsupported protection type
                    detail_type = detail.get('type', None)
                    if detail_type not in ['edit', 'move']:
                        log_exclusions.add(f"unsupported protection type: {detail_type}")
                        break

                    # only process non-infinite protections
                    detail_expiry = detail.get('expiry', None)
                    if detail_expiry == float('inf'):
                        continue

                    # only process high protection levels
                    detail_level = detail.get('level', None)
                    if detail_level in ['extendedconfirmed', 'templateeditor', 'sysop']:
                        filtered_details.append(detail)

                # skip entire log entry
                if log_exclusions:
                    continue
                # skip if there were too many protections in details
                if len(filtered_details) > 2:
                    logging.error(f"unexpected number of details for {log}: {len(filtered_details)}")
                    continue
                # store expirations
                if filtered_details:
                    primary_expiry = self.get_primary_expiry_from_details(filtered_details)
                    self.page_protections[title] = (log['logid'], primary_expiry, filtered_details)
            except Exception as e:
                logging.error(f"error processing log entry for {log}: {e}")

        logging.info(f"total logs: {count}, expirations: {len(self.page_protections)}")

        if self.backtest and count == 0:
            logging.info("done backtest")
            sys.exit(0)

    def get_primary_expiry_from_details(self, protections):
        """
        Gets the primary expiry timestamp from protection details, preferring 'edit' over 'move'.
        Infinite timestamps are ignored.

        Parameters:
        protections (list): List of protection details with 'expiry' and 'type'.

        Returns:
        float or None: The primary expiry timestamp, or None if no expiry is found.
        """
        move_expiry = None

        for protection in protections:
            expiry = protection.get('expiry')
            if expiry == float('inf'):
                continue
            if ProtectionFunctions.protection_level(protection.get('level')) <= ProtectionFunctions.protection_level('autoconfirmed'):
                continue
            if protection.get('type') == 'edit':
                return expiry
            if protection.get('type') == 'move':
                move_expiry = expiry

        return move_expiry

    def find_next_expired_protection(self):
        """
        Finds the page with the oldest expired protection.

        Scans through all pages to determine the earliest protection expiration timestamp.
        Logs a warning if there are multiple expiry timestamps for a page.

        Returns:
        str: Title of the page with the oldest expired protection, or None if no such page exists.
        """
        if not self.page_protections:
            return None

        oldest_page = min(self.page_protections, key=lambda k: self.page_protections[k][1])

        current_time = int(time.time())
        if self.backtest:
            current_time = self.backtest_time
        if self.future_seconds and self.logs.queries:
            current_time = int(time.time()) + self.future_seconds

        if self.page_protections[oldest_page][1] < current_time:
            logging.info(f"oldest: title = {oldest_page}, current_time = {current_time}, position = {self.logs.position}, protections = {self.page_protections[oldest_page]}")
            return oldest_page

        return None

    def evaluate_protection_restoration(self, expired_title):
        """
        Restores protection for a page if expired protection should be restored.

        Attempts to restore the protection level of a page based on the logs and compares
        with previous protection details.

        Parameters:
        expired_title (str): The title of the page with expired protection.

        Returns:
        bool: True if protection restored, False otherwise.
        """

        def unpack_protections(protections):
            protection_dict = {p['type']: (p.get('level'), p.get('expiry')) for p in protections}
            return (
                *protection_dict.get('edit', (None, None)),
                *protection_dict.get('move', (None, None))
            )

        def format_expiry(expiry):
            if expiry in ['infinity', 'infinite', 'indefinite', 'never', '', float('inf')]:
                return 'indefinite'
            elif isinstance(expiry, (int, float)):
                dt = datetime.utcfromtimestamp(expiry)
                iso_string = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                return iso_string
            logging.warning(f"unexpected expiry value: {expiry}")
            return str(expiry)

        expired_logid, protection_expiry, protections = self.page_protections.pop(expired_title)

        # current time
        current_time = int(time.time())
        if self.backtest:
            current_time = self.backtest_time
        if self.future_seconds and self.logs.queries:
            current_time = protection_expiry

        # clearly stale expirations
        most_recent_expiry = max(detail['expiry'] for detail in protections)
        if most_recent_expiry < current_time - RECENT_INTERVAL.total_seconds() and current_time != protection_expiry:
            logging.info(f"stale expiration: {expired_title} | {protections}")
            return False

        # deleted pages
        page = pywikibot.Page(self.site, expired_title)
        if not page.exists():
            logging.info(f"skipping due to page not existing: {expired_title}")
            return False

        # latest protection
        latest_user = None
        latest_timestamp = None
        latest_comment = None
        latest_edit_level = None
        latest_edit_expiry = None
        latest_move_level = None
        latest_move_expiry = None

        # ignore short-lived protections
        short_lived = 0

        # previous protection
        previous_user = None
        previous_comment = None
        previous_edit_level = None
        previous_edit_expiry = None
        previous_move_level = None
        previous_move_expiry = None

        # iterate across protection logs
        log_position = 0
        for log, details in self.logs.fetch_page_logs(page=page):
            logid = log['logid']
            title = log['title']
            action = log['action']
            timestamp = ProtectionFunctions.iso_to_timestamp(log['timestamp'])

            # backtest: ignore logs after a hypothetical restoration; this is an approximation
            if self.backtest and logid > expired_logid:
                if isinstance(protection_expiry, (int, float)) and timestamp > protection_expiry:
                    logging.info(f"backtest ignoring subsequent protection: {expired_title} | {log} | {details}")
                    continue

            # ignore transient protections by same user
            if latest_user is not None and latest_user == log['user'] and latest_timestamp - timestamp < 900 and short_lived < 2 and action in ['modify', 'protect'] and not latest_comment.lower().startswith('temporary'):
                logging.info(f"ignoring short-lived protection by same user: {expired_title} | {log} | {details}")
                short_lived += 1
                continue

            # shared checks
            if action not in ['modify', 'protect']:
                logging.info(f"skipping due to previous non-protection: {action} | {expired_title} | {log}")
                return False
            if not details:
                logging.error(f"skipping due to no details: {expired_title} | {log}")
                return False
            if any('cascade' in p for p in details):
                logging.info(f"skipping due to cascading protection: {action} | {expired_title} | {details} | {log}")
                return False

            try:
                if log_position == 0:
                    log_position += 1
                    if logid != expired_logid:
                        logging.info(f"skipping due to more recent protection: {expired_title}")
                        return False
                    if log['user'] == self.site.username():
                        logging.warning(f"skipping due to most recent protection from self: {expired_title}")
                        return False
                    latest_user = log['user']
                    latest_timestamp = timestamp
                    latest_comment = log['comment'] or ''
                    ( latest_edit_level, latest_edit_expiry,
                      latest_move_level, latest_move_expiry ) = unpack_protections(details)
                    continue
                elif log_position == 1:
                    log_position += 1
                    previous_user = log['user']
                    previous_comment = log['comment']
                    ( previous_edit_level, previous_edit_expiry,
                      previous_move_level, previous_move_expiry ) = unpack_protections(details)
                    break
            except Exception as e:
                logging.error(f"error processing log entry for {log}: {e}")

        # nothing to restore
        if not previous_user:
            logging.info(f"skipping due to no previous protection: {action} | {expired_title} | {details} | {log}")
            return False

        # current protection levels
        restore_edit_level = None
        restore_edit_expiry = None
        restore_move_level = None
        restore_move_expiry = None
        if latest_edit_expiry is not None and latest_edit_expiry > current_time:
            restore_edit_level, restore_edit_expiry = latest_edit_level, latest_edit_expiry
        if latest_move_expiry is not None and latest_move_expiry > current_time:
            restore_move_level, restore_move_expiry = latest_move_level, latest_move_expiry

        # restoration logic
        reprotect = False
        logging.info(f"{expired_title} | edit values: previous_edit_level = {previous_edit_level}, latest_edit_level = {latest_edit_level}, previous_edit_expiry = {previous_edit_expiry}, latest_edit_expiry = {latest_edit_expiry}, current_time = {current_time}, restore_edit_level = {restore_edit_level}, restore_edit_expiry = {restore_edit_expiry}")
        logging.info(f"{expired_title} | move values: previous_move_level = {previous_move_level}, latest_move_level = {latest_move_level}, previous_move_expiry = {previous_move_expiry}, latest_move_expiry = {latest_move_expiry}, current_time = {current_time}, restore_move_level = {restore_move_level}, restore_move_expiry = {restore_move_expiry}")
        if previous_edit_level and ProtectionFunctions.protection_level(previous_edit_level) < ProtectionFunctions.protection_level(latest_edit_level) and (latest_edit_expiry is None or previous_edit_expiry > latest_edit_expiry) and previous_edit_expiry > current_time + MINIMUM_DURATION.total_seconds():
            restore_edit_level = previous_edit_level
            restore_edit_expiry = previous_edit_expiry
            if previous_move_level and (latest_move_expiry is None or previous_move_expiry > latest_move_expiry) and previous_move_expiry > current_time + MINIMUM_DURATION.total_seconds() and previous_move_level != "autoconfirmed":
                restore_move_level = previous_move_level
                restore_move_expiry = previous_move_expiry
            reprotect = True
        elif previous_move_level and ProtectionFunctions.protection_level(previous_move_level) < ProtectionFunctions.protection_level(latest_move_level) and (latest_move_expiry is None or previous_move_expiry > latest_move_expiry) and previous_move_expiry > current_time + MINIMUM_DURATION.total_seconds() and previous_move_level != "autoconfirmed" and restore_move_level != "autoconfirmed":
            restore_move_level = previous_move_level
            restore_move_expiry = previous_move_expiry
            reprotect = True

        # autoconfirmed is required for all moves already
        if restore_move_level == "autoconfirmed":
            restore_move_level = None
            restore_move_expiry = None

        # perform restoration
        if reprotect:
            protections = {}
            expirys = []
            # edit protection
            if restore_edit_level:
                protections['edit'] = restore_edit_level
                expiry_string = format_expiry(restore_edit_expiry)
                expirys.append(expiry_string)
            # move protection
            if restore_move_level:
                protections['move'] = restore_move_level
                expiry_string = format_expiry(restore_move_expiry)
                if expiry_string not in expirys:
                    expirys.append(expiry_string)
            # expired protection expiry
            protection_expiry = format_expiry(protection_expiry)
            # reason
            if previous_user == self.site.username():
                reason = previous_comment
            else:
                reason = f"Restoring protection by [[User:{previous_user}|{previous_user}]]"
                if previous_comment:
                    reason += f": {previous_comment}"
            # apply protection
            logging.info(f"protecting: {expired_title} | expired: {protection_expiry} | levels: {protections} | expiry: {expirys} | reason: {reason} | short_lived: {short_lived}")
            if not DRY_RUN:
                self.protect_rate_limit.throttle()
                self.site.protect(page, protections, reason, expiry="|".join(expirys))
            return True

        # conditions not met
        logging.info(f"skipping due to conditions being unmet: {expired_title}");
        return False

    def process_expirations(self):
        # handle protection expirations
        while True:
            # fetch expirations
            manager.update_page_protections()
            # process all available expirations
            while expired := manager.find_next_expired_protection():
                manager.evaluate_protection_restoration(expired)


if __name__ == "__main__":
    try:
        args = parse_args()
        site = login()
        manager = ProtectionManager(site, backtest=args.backtest, future_days=args.future)

        logging.info(f"starting: DRY_RUN={DRY_RUN} | LOOKBACK_INTERVAL={LOOKBACK_INTERVAL} | RECENT_INTERVAL={RECENT_INTERVAL} | args={args}")
        manager.process_expirations()
    except Exception as e:
        logging.error(f"unhandled exception: {e}")
        logging.error(f"traceback: {traceback.format_exc()}")
        time.sleep(300)
        sys.exit(1)
