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
- The protection level is the same as or lower than the previous level.
- There is a more recent protection action.
- Any of the most recent actions is a cascading protection.
- The protection would require differing edit and move expirations (not supported by pywikibot).
- Serious errors occur during the restoration process.

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

from datetime import datetime, timedelta


# configuration
LOOKBACK_INTERVAL = timedelta(days=366) # log period to review
RECENT_INTERVAL = timedelta(days=90) # act on protections that have expired within this period
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


class ProtectionFunctions:
    """
    Utility class for general functions used across protection-related classes.
    """

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
        levels = {'autoconfirmed': 0, 'extendedconfirmed': 1, 'templateeditor': 2, 'sysop': 3}

        return levels.get(level, -1)


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
        self.next_fetch_time = datetime.now() - LOOKBACK_INTERVAL

    def fetch_all_logs(self):
        """
        Retrieve all protection logs within the configured date range.

        Yields:
        tuple: A tuple containing log data and details.
        """
        end = datetime.now()
        start = self.next_fetch_time
        self.next_fetch_time = end
        logging.info(f"query {start} to {end}")
        for log in self.site.logevents(logtype='protect', end=end, start=start, reverse=True):
            log_result = self.parse_log(log)
            if log_result:
                yield log_result
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
        None: If no details could be extracted, or the type of protection isn't 'edit' or 'move'.
        """
        level_map = {
            'Block new and unregistered users': 'autoconfirmed',
            'Block all non-admin users': 'sysop'
        }
        patterns = [
            r'\[(?P<type>edit|move)=(?P<level>\w+)\] \((?P<expiry>expires[^\)]+\(UTC\)|indefinite)\)',
            r'\[(?P<type>Edit|Move)=(?P<level>Block new and unregistered users|Block all non-admin users)\] \((?P<expiry>expires[^\)]+\(UTC\)|indefinite)\)'
        ]
        details = []

        for pattern in patterns:
            for match in re.finditer(pattern, description):
                expiry = match.group('expiry')
                if expiry == 'indefinite':
                    expiry = float('inf')
                else:
                    expiry = datetime.strptime(expiry, 'expires %H:%M, %d %B %Y (UTC)').timestamp()

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

        # unprotection
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

        # this is almost entirely legacy formatted create and upload protections
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
        self.future_time = timedelta(days=future_days).total_seconds()
        self.logs = ProtectionLogs(site)
        self.page_protections = {}

    def update_page_protections(self):
        """
        Process all protection logs and update the internal list of pages with active protections.

        This method processes each log entry, handles unprotection, move protection, and updates
        the list of pages with active protections based on their expiration timestamps.
        """
        count = 0
        for log, details in self.logs.fetch_all_logs():
            count += 1
            title = log['title']

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

                    # skip stale expirations
                    if detail_expiry < (datetime.now() - RECENT_INTERVAL).timestamp():
                        logging.debug(f"stale expiration: {title} | {detail_expiry}")
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
                    self.page_protections[title] = (log['logid'], filtered_details)
            except Exception as e:
                logging.error(f"error processing log entry for {log}: {e}")

        logging.info(f"total logs: {count}, expirations: {len(self.page_protections)}")

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
        oldest_expiry = float('inf')
        oldest_page = None

        for title, (logid, protections) in self.page_protections.items():
            expiry = self.get_primary_expiry_from_details(protections)
            # this should never happen
            if expiry is None or expiry == float('inf'):
                logging.error(f"invalid primary expiration: {title} | {logid} | {protections}")
                continue
            # expire based on the edit timestamp if there are two different timestamps
            if expiry < oldest_expiry and expiry < time.time() + self.future_time:
                oldest_expiry = expiry
                oldest_page = title

        logging.info(f"oldest: {oldest_page} {oldest_expiry} {self.page_protections.get(oldest_page)}")
        return oldest_page

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
        expired_logid, protections = self.page_protections.pop(expired_title)
        page = pywikibot.Page(self.site, expired_title)
        protection_expiry = self.get_primary_expiry_from_details(protections)

        # deleted pages
        if not page.exists():
            logging.info(f"skipping due to page not existing: {expired_title}")
            return False

        edit_level = None
        edit_expiry = None
        move_level = None
        move_expiry = None
        previous_edit_level = None
        previous_edit_expiry = None
        previous_move_level = None
        previous_move_expiry = None

        index = -1
        found_expired_logid = False
        user = None

        for log, details in self.logs.fetch_page_logs(page=page):
            logid = log['logid']
            title = log['title']
            action = log['action']

            # backtest: ignore logs after a hypothetical restoration; this is an approximation
            if self.backtest and logid > expired_logid:
                timestamp = ProtectionFunctions.iso_to_timestamp(log['timestamp'])
                if isinstance(protection_expiry, (int, float)) and timestamp > protection_expiry:
                    logging.info(f"backtest ignoring subsequent protection: {expired_title} | {log} | {details}")
                    continue

            # start index at 0
            index += 1

            # make sure we see the expired logid
            if logid == expired_logid:
                found_expired_logid = True

            # checking top two logs should be sufficient
            if index > 1:
                break
            logging.debug(f"log {index} | {logid} | {action} | {details}")

            try:
                if index == 0:
                    if logid != expired_logid:
                        logging.info(f"skipping due to more recent protection: {expired_title}")
                        return False
                    if not details:
                        logging.error(f"skipping due to no details for expired protection: {expired_title}")
                        return False
                    if self.site.username() == log['user']:
                        logging.warning(f"skipping due to most recent protection from self: {expired_title}")
                        return False
                    for detail in details:
                        detail_type = detail.get('type', None)
                        detail_level = detail.get('level', None)
                        detail_expiry = detail.get('expiry', None)
                        if detail_type == 'edit':
                            edit_level = detail_level
                            edit_expiry = detail_expiry
                        if detail_type == 'move':
                            move_level = detail_level
                            move_expiry = detail_expiry
                        if 'cascade' in detail:
                            logging.info(f"skipping due to cascading protection: {action} | {expired_title} | {details} | {log}")
                            return False
                elif index == 1:
                    if action not in ['modify', 'protect']:
                        logging.info(f"skipping due to previous non-protection: {action} | {expired_title} | {log}")
                        return False
                    if not details:
                        logging.error(f"skipping due to no details for previous protection: {expired_title}")
                        return False

                    # details for the reason
                    user = log['user']
                    comment = log['comment']

                    for detail in details:
                        detail_type = detail.get('type', None)
                        detail_level = detail.get('level', None)
                        detail_expiry = detail.get('expiry', None)
                        if detail_type == 'edit':
                            previous_edit_level = detail_level
                            previous_edit_expiry = detail_expiry
                        if detail_type == 'move':
                            previous_move_level = detail_level
                            previous_move_expiry = detail_expiry
                        if 'cascade' in detail:
                            logging.info(f"skipping due to cascading protection: {action} | {expired_title} | {details} | {log}")
                            return False
            except Exception as e:
                logging.error(f"error processing log entry for {log}: {e}")

        # final decision on restoring protection
        if not user:
            logging.info(f"skipping due to no previous protection: {action} | {expired_title} | {details} | {log}")
            return False
        if not comment:
            comment = "empty reason"
        reprotect = False

        # check current protection status
        restore_edit_level = None
        restore_edit_expiry = None
        restore_move_level = None
        restore_move_expiry = None

        # normal operation
        if not self.backtest:
            current_protection = page.protection()
            if 'edit' in current_protection:
                restore_edit_level, restore_edit_expiry = current_protection['edit']
            if 'move' in current_protection:
                restore_move_level, restore_move_expiry = current_protection['move']
            # convert timestamps
            try:
                if isinstance(restore_edit_expiry, str) and restore_edit_expiry[0].isdigit():
                    restore_edit_expiry = ProtectionFunctions.iso_to_timestamp(restore_edit_expiry)
                if isinstance(restore_move_expiry, str) and restore_move_expiry[0].isdigit():
                    restore_move_expiry = ProtectionFunctions.iso_to_timestamp(restore_move_expiry)
            except Exception as e:
                logging.error(f"skipping due to error converting protection timestamps: {current_protection} | {e}")
                return False
        # backtesting
        else:
            if edit_expiry is not None and edit_expiry > protection_expiry:
                restore_edit_level, restore_edit_expiry = edit_level, edit_expiry
            if move_expiry is not None and move_expiry > protection_expiry:
                restore_move_level, restore_move_expiry = move_level, move_expiry

        # should never happen
        if not found_expired_logid:
            logging.error(f"skipping due to missing expired logid: {expired_logid} | {expired_title}");
            return False

        # restoration logic
        if previous_edit_level and ProtectionFunctions.protection_level(previous_edit_level) < ProtectionFunctions.protection_level(edit_level) and previous_edit_expiry > edit_expiry and previous_edit_expiry > time.time() + 3600:
            restore_edit_level = previous_edit_level
            restore_edit_expiry = previous_edit_expiry
            if previous_move_level and previous_move_expiry > move_expiry and previous_move_expiry > time.time() + 3600 and previous_move_level != "autoconfirmed":
                restore_move_level = previous_move_level
                restore_move_expiry = previous_move_expiry
            reprotect = True
        elif previous_move_level and ProtectionFunctions.protection_level(previous_move_level) < ProtectionFunctions.protection_level(move_level) and previous_move_expiry > move_expiry and previous_move_expiry > time.time() + 3600 and previous_move_level != "autoconfirmed" and restore_move_level != "autoconfirmed":
            restore_move_level = previous_move_level
            restore_move_expiry = previous_move_expiry
            reprotect = True

        # autoconfirmed is required for all moves already
        if restore_move_level == "autoconfirmed":
            restore_move_level = None
            restore_move_expiry = None

        # perform restoration
        if reprotect:
            protections = {'edit': restore_edit_level, 'move': restore_move_level}
            if restore_edit_expiry in ['infinity', 'infinite', 'indefinite', 'never', '', float('inf')]:
                restore_edit_expiry = 'indefinite'
            if restore_move_expiry in ['infinity', 'infinite', 'indefinite', 'never', '', float('inf')]:
                restore_move_expiry = 'indefinite'
            if restore_edit_expiry is not None and restore_move_expiry is not None:
                if restore_edit_expiry != restore_move_expiry:
                    logging.warning(f"skipping due to differing expiration timestamps: edit = {restore_edit_expiry}, move = {restore_move_expiry}")
                    return False
            expiry = None
            if isinstance(restore_edit_expiry, (int, float)):
                restore_edit_expiry = datetime.utcfromtimestamp(restore_edit_expiry)
            if isinstance(restore_move_expiry, (int, float)):
                restore_move_expiry = datetime.utcfromtimestamp(restore_move_expiry)
            if restore_edit_expiry:
                expiry = restore_edit_expiry
            elif restore_move_expiry:
                expiry = restore_move_expiry
            reason = f"Restoring protection by [[User:{user}|{user}]]: {comment}"
            if protection_expiry == float('inf'):
                expired_expiry = "indefinite"
            elif isinstance(protection_expiry, (int, float)):
                expired_expiry = datetime.utcfromtimestamp(protection_expiry)
            logging.info(f"protecting: {expired_title} | expired: {expired_expiry} | levels: {protections} | expiry: {expiry} | reason: {reason}")
            if not DRY_RUN:
                self.site.protect(page, protections, reason, expiry=expiry)
            return True

        # conditions not met
        logging.info(f"skipping due to conditions being unmet: {expired_title}");
        return False


if __name__ == "__main__":
    try:
        args = parse_args()
        site = login()
        manager = ProtectionManager(site, backtest=args.backtest, future_days=args.future)

        # log various options for debugging
        logging.info(f"starting: DRY_RUN={DRY_RUN} | LOOKBACK_INTERVAL={LOOKBACK_INTERVAL} | RECENT_INTERVAL={RECENT_INTERVAL} | args={args}")

        # handle protection expirations
        while True:
            # fetch expirations
            manager.update_page_protections()
            # process all available expirations
            while expired := manager.find_next_expired_protection():
                if manager.evaluate_protection_restoration(expired):
                    # longer wait between reprotection actions
                    time.sleep(0 if DRY_RUN else 300)
                else:
                    # shorter wait otherwise
                    time.sleep(0 if DRY_RUN else 1)
            # wait before checking log again
            time.sleep(300)
    except Exception as e:
        logging.error(f"unhandled exception: {e}")
        time.sleep(300)
        sys.exit(1)
