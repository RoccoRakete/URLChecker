import argparse
import json
import os
import re
import sys
import warnings
from enum import Enum
from typing import List, Optional, Union

import httpx as httpx
import pydantic as pydantic
import socket
import time

from httpx import ConnectTimeout, ReadTimeout, ConnectError
from pydantic.json import pydantic_encoder

# Dateiname der Textdatei mit den URLs und Keywords
url_file = "urls.txt"
results_file = "results.txt"


def getDomain(givenURL: str) -> Union[str, None]:
    match = re.search('^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n]+)', givenURL)
    if match:
        return match.group(1)
    else:
        return None  # oder eine Fehlermeldung


def isDomain(string: str):
    if str is None:
        return False
    elif re.search(r'^(?!-)[A-Za-z0-9-]+([-.][a-z0-9]+)*\\.[A-Za-z]{2,6}$', string):
        return True
    else:
        return False


class ProblemType(Enum):
    NO_DNS_RECORD = 0
    CONNECT_TIMEOUT = 1
    READ_TIMEOUT = 2
    BLOCKED_BY = 3
    PARKED_DOMAIN = 4
    NO_MARKER_MATCH = 5
    MISC = 6
    WTF = 7


class DomainCheckResult(pydantic.BaseModel):
    # TODO: Add validation for domain / url
    domain: str
    wasChecked: bool = False
    problemType: Optional[ProblemType]
    responsecode: Optional[int]
    ip_address: Optional[str]
    connectMillis: Optional[float]
    blockedBy: Optional[str]
    # parkedType: Optional[int]
    isMarkerFound: Optional[bool]
    redirectedToDomain: Optional[str]
    preferredProtocol: Optional[str]

    def isOnline(self) -> Union[bool, None]:
        if self.wasChecked is None:
            return None
        elif self.problemType is None:
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
        problemType = self.problemType
        if problemType is not None:
            if problemType == ProblemType.BLOCKED_BY:
                return f'{self.problemType.name} -> {self.blockedBy}'
            else:
                return problemType.name
        else:
            return None

    def getAdditionalFailureReasonStr(self) -> Union[str, None]:
        # TODO: Add more functionality
        str = ''
        if self.redirectedToDomain is not None:
            str += f'REDIRECT: {self.redirectedToDomain}'
        if self.blockedBy is not None:
            str += f' | BLOCKED_BY: {self.blockedBy}'
        if len(str) > 0:
            return str
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
        return f'{self.domains[0]} | {self.getStatusText()}'

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

    def getStatusText(self) -> str:
        onlinestatus: Union[bool, None] = self.isOnline()
        if onlinestatus is None:
            return f'UNCHECKABLE -> {self.getFailureReasonStr()}'
        elif onlinestatus is True:
            return 'ONLINE'
        else:
            return f'OFFLINE -> {self.getFailureReasonStr()}'

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
        # mainDomain = domainCheckInfo.domains[0]
        for domain in domainCheckInfo.domains:
            domainCheckResult = DomainCheckResult(domain=domain)
            try:
                # Add checkResult so whatever happens we will have a result in our list
                # TODO: Add this via finally block to make it more reliable - we dont want to have this if e.g. this script gets killed in the middle

                # DNS-Lookup testen
                try:
                    ip_address = socket.gethostbyname(domain)
                    domainCheckResult.ip_address = ip_address
                except socket.gaierror:
                    # DNS Lookup failed -> No need to do further tests
                    domainCheckResult.problemType = ProblemType.NO_DNS_RECORD
                    continue

                # Verbindungszeit testen
                start_time = time.time()
                try:
                    # verify=False -> Ignore certificate warnings
                    req = httpx.get("https://" + domain, timeout=self.timeout, verify=False, follow_redirects=True)
                except ConnectTimeout:
                    domainCheckResult.problemType = ProblemType.CONNECT_TIMEOUT
                    continue
                except ReadTimeout:
                    domainCheckResult.problemType = ProblemType.READ_TIMEOUT
                    continue
                except ConnectError:
                    domainCheckResult.problemType = ProblemType.WTF
                    continue
                html = req.text
                domainCheckResult.responsecode = req.status_code
                end_time = time.time()
                time_taken = end_time - start_time
                # if time_taken > self.timeout:
                #     domainCheckResult.isTimeout = True
                # else:
                #     domainCheckResult.isTimeout = False
                domainCheckResult.connectMillis = time_taken
                currentDomain = req.url.host
                if currentDomain != domain:
                    domainCheckResult.redirectedToDomain = currentDomain
                blockedBy = self.getBlockedBy(req)
                if blockedBy is not None:
                    domainCheckResult.problemType = ProblemType.BLOCKED_BY
                    domainCheckResult.blockedBy = blockedBy
                elif self.looksLikeParkedDomain(html):
                    domainCheckResult.problemType = ProblemType.PARKED_DOMAIN

                # TODO: Check for Cloudflare and similar
            finally:
                domainCheckResult.wasChecked = True
                domainCheckInfo.checkResults.append(domainCheckResult)
            # TODO: Check all domains
            break

    def looksLikeParkedDomain(self, html: str):
        # TODO: Add better detection of parked domains
        if 'sedoparking.com' in html or 'sedoParkingUrl' in html:
            return True
        elif 'window.park' in html and '/js/parking' in html:
            return True
        else:
            return False

    def getBlockedBy(self, req) -> Union[str, None]:
        """ Detect DNS blocks and blocks by e.g. Cloudflare. """
        server = req.headers.get('Server')
        html = req.text
        if req.status_code == 403 and server is not None and 'cloudflare' in server and 'cf-error' in html:
            return 'Cloudflare'
        elif req.status_code == 403 and server is not None and 'ddos-guard' in server and 'link=\"https://ddos-guard.net/' in html:
            return 'DDoS-Guard'
        else:
            return None


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
            keywords = []
            if ' ' in line:
                url, keyword = line.split(" ", 1)  # die erste Leerzeichen-getrennte Zeichenkette als URL, den Rest als Keyword nehmen
                keywords = [keyword]
            else:
                url = line
            domain = getDomain(url)
            if domain is None:
                print(f'Skipping line due to invalid domain: {domain}')
                continue
            dsi = DomainCheckInfo(url=url, domains=[domain], keywords=keywords)
            itemsToCheck.append(dsi)
    if len(itemsToCheck) == 0:
        print("Keine Domains zum prüfen gefunden -> Ende")
        sys.exit()

    pos = 0
    with open(results_file, "w") as file:
        for dsi in itemsToCheck:
            print(f"Arbeite an item {pos + 1} von {len(itemsToCheck)} | {dsi.url}")
            checker.checkURL(dsi)
            print(f"--> {dsi.getStatusText()}")
            text = ''
            if pos > 0:
                text += '\n'
            text += str(dsi)
            file.write(text)
            pos += 1

    with open('results.json', 'w') as ofile:
        json.dump(itemsToCheck, ofile, default=pydantic_encoder)

    print(f"Testergebnisse wurden in den Dateien {results_file} und results.json gespeichert.")
