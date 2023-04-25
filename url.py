import argparse
import json
import os
import re
import sys
import warnings
from typing import List, Optional, Union

import pydantic as pydantic
import requests
import socket
import time

from pydantic.json import pydantic_encoder
from requests import ConnectTimeout, ReadTimeout

# Dateiname der Textdatei mit den URLs und Keywords
url_file = "urls.txt"
results_file = "results.txt"


def getDomain(givenURL: str) -> Union[str, None]:
    """ Returns url without protocol. """
    return re.search('(?i)https?://([^/]+).*', givenURL).group(1)


class DomainCheckResult(pydantic.BaseModel):
    # TODO: Add validation for domain / url
    domain: str
    responsecode: Optional[int]
    ip_address: Optional[str]
    isTimeout: Optional[bool]
    connectMillis: Optional[float]
    isBlockedBy: Optional[int]
    isParked: Optional[bool]
    # parkedType: Optional[int]
    isMarkerFound: Optional[bool]
    redirectedTo: Optional[str]
    preferredProtocol: Optional[str]

    def isOnline(self) -> bool:
        if not self.isTimeout and self.ip_address is not None:
            return True
        else:
            return False

    def isOriginalWebsite(self) -> Union[bool, None]:
        # TODO: Add 'False' status
        if self.isMarkerFound:
            return True
        else:
            return None

    def getFailureReasonStr(self) -> Union[str, None]:
        if self.ip_address is None:
            return 'NO_DNS_RECORD'
        elif self.isTimeout:
            return 'TIMEOUT'
        elif self.isParked:
            return 'PARKED'
        else:
            return None


class DomainCheckInfo(pydantic.BaseModel):
    url: str
    domains: List[str]
    seconds_taken: Optional[int]
    keywords: Optional[List[str]]
    regexes: Optional[List[str]]
    status: Optional[int]
    checkResults: List[DomainCheckResult] = []

    def __str__(self):
        if self.isOnline() is True:
            return f'{self.domains[0]} | {self.getOnlineStatus()}'
        else:
            return f'{self.domains[0]} | {self.getOnlineStatus()} | {self.getFailureReasonStr()}'

    def getURL(self) -> str:
        return self.url

    def isOnline(self) -> Union[bool, None]:
        # TODO
        offlineCount = 0
        for cr in self.checkResults:
            if cr.isOnline() is True:
                return True
            elif cr.isOnline() is False:
                offlineCount += 1
        if offlineCount == len(self.domains):
            # All offline
            return False
        else:
            # Some offline some unchecked -> Unclear status
            return None

    def getOnlineStatus(self) -> str:
        onlinestatus: Union[bool, None] = self.isOnline()
        if onlinestatus is None:
            return 'UNCHECKABLE'
        elif onlinestatus is True:
            return 'ONLINE'
        else:
            return 'OFFLINE'

    def getFailureReasonStr(self) -> Union[str, None]:
        for checkResult in self.checkResults:
            failureReason = checkResult.getFailureReasonStr()
            if failureReason is not None:
                return failureReason
        return None


class URLChecker:

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        # Ignore ssl warning loggers
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    # def main(self):
    #     pass

    def checkURL(self, domainCheckInfo: DomainCheckInfo):
        for domain in domainCheckInfo.domains:
            domainCheckResult = DomainCheckResult(domain=domain)
            domainCheckInfo.checkResults.append(domainCheckResult)
            # Add checkResult so whatever happens we will have a result in our list
            # TODO: Add this via finally block to make it more reliable - we dont want to have this if e.g. this script gets killed in the middle

            # DNS-Lookup testen
            try:
                ip_address = socket.gethostbyname(domain)
                domainCheckResult.ip_address = ip_address
            except socket.gaierror:
                # DNS Lookup failed -> No need to do further tests
                continue

            # Verbindungszeit testen
            start_time = time.time()
            try:
                # verify=False -> Ignore certificate warnings
                response = requests.get("https://" + domain, timeout=self.timeout, verify=False)
            except ConnectTimeout:
                domainCheckResult.isTimeout = True
                continue
            except ReadTimeout:
                domainCheckResult.isTimeout = True
                continue
            domainCheckResult.responsecode = response.status_code
            end_time = time.time()
            time_taken = end_time - start_time
            # if time_taken > self.timeout:
            #     domainCheckResult.isTimeout = True
            # else:
            #     domainCheckResult.isTimeout = False
            domainCheckResult.connectMillis = time_taken
            # TODO: Check all domains
            break

    def looksLikeParkedDomain(self, html: str):
        # TODO: Add detection of parked domains
        if 'todo' in html:
            return True
        else:
            return False


if __name__ == '__main__':

    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('-t', '--timeout', help='Read-Timeout in seconds.', type=int, default=30)
    args = my_parser.parse_args()
    # checker = URLChecker(timeout=args.timeout)
    checker = URLChecker(timeout=1)

    # URLs und zugehörige Keywords aus der Textdatei lesen
    itemsToCheck = []
    if not os.path.isfile(url_file):
        print(f"Datei {url_file} nicht gefunden -> Ende")
        sys.exit()
    # Parse URLs from textdocument
    with open(url_file, "r") as file:
        for line in file:
            line = line.strip()
            if line == "":
                continue
            if ' ' in line:
                url, keyword = line.split(" ", 1)  # die erste Leerzeichen-getrennte Zeichenkette als URL, den Rest als Keyword nehmen
                dsi = DomainCheckInfo(url=url, domains=[getDomain(url)], keywords=[keyword])
            else:
                url = line
                dsi = DomainCheckInfo(url=url, domains=[getDomain(url)])
            itemsToCheck.append(dsi)
    if len(itemsToCheck) == 0:
        print("Keine Domains zum prüfen gefunden -> Ende")
        sys.exit()

    pos = 0
    with open(results_file, "w") as file:
        for dsi in itemsToCheck:
            print(f"Arbeite an item {pos + 1} von {len(itemsToCheck)} | {dsi.url}")
            checker.checkURL(dsi)
            text = ''
            if pos > 0:
                text += '\n'
            text += str(dsi)
            file.write(text)
            pos += 1

    with open('results.json', 'w') as ofile:
        json.dump(itemsToCheck, ofile, default=pydantic_encoder)

    print(f"Testergebnisse wurden in den Dateien {results_file} und results.json gespeichert.")
