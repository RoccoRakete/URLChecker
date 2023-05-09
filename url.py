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


def regexDomain(urlOrDomain: str) -> Union[str, None]:
    """ Returns domain from given URL or domain. """
    return re.search('(?i)(?:https?://)?([^/]+).*', urlOrDomain).group(1)


def isDomain(string: str) -> bool:
    if string is None:
        return False
    elif re.search(r'^(?!-)[A-Za-z0-9-.]+[a-z0-9]$', string):
        # Very cheap RegEx to roughly validate a domain.
        # TODO: Add a more reliable RegEx.
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
    isMarkerFound: Optional[Union[bool, None]]
    redirectedToDomain: Optional[str]
    # preferredProtocol: Optional[str]

    def isOnline(self) -> bool:
        if self.problemType is None:
            return True
        else:
            return False

    def isOriginalWebsite(self) -> Union[bool, None]:
        # TODO: Add 'False' status
        if self.isMarkerFound is None or self.isMarkerFound:
            return True
        elif self.isMarkerFound:
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
        offlineCount = 0
        for cr in self.checkResults:
            if cr.isOnline() is True:
                # At least one item is online
                return True
            else:
                offlineCount += 1
        if offlineCount == len(self.domains):
            # All offline
            return False
        else:
            # Some offline, some unchecked -> Unclear status
            return None

    def getStatusText(self) -> str:
        onlinestatus = self.isOnline()
        newMainDomain = self.getNewMainDomain()
        includeNewMainDomainInfoInText = True
        if onlinestatus is None:
            statustext = f'UNCHECKABLE -> {self.getFailureReasonStr()}'
        elif onlinestatus is True:
            statustext = 'ONLINE'
        else:
            statustext = f'OFFLINE -> {self.getFailureReasonStr()}'
            includeNewMainDomainInfoInText = False
        if newMainDomain is not None and includeNewMainDomainInfoInText:
            statustext += f' | NEW_MAIN_DOMAIN: {newMainDomain}'
        return statustext

    def getFailureReasonStr(self) -> Union[str, None]:
        for checkResult in self.checkResults:
            failureReasonStr = checkResult.getFailureReasonStr()
            if failureReasonStr is not None:
                return failureReasonStr
        return None

    def getNewMainDomain(self, ignoreWWW: bool = False) -> Union[str, None]:
        """ Returns domain which is thought to be the new main domain of checked main domain.
         For example if you check google.de and google.com and google.de always redirects to google.com, google.com would be considered the new main domain.
         """
        mainDomain = self.domains[0]
        if ignoreWWW:
            # TODO
            mainDomain = re.sub(r'^www\.', '', mainDomain)
        for cr in self.checkResults:
            redirectDomain = cr.redirectedToDomain
            if redirectDomain is None:
                continue
            if ignoreWWW:
                redirectDomain = re.sub(r'^www\.', '', redirectDomain)
            isDifferentDomain = redirectDomain != mainDomain
            if cr.redirectedToDomain is not None and isDifferentDomain and cr.isOriginalWebsite():
                return cr.redirectedToDomain
        return None


class URLChecker:

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        # TODO: Add functionality
        self.ignoreWWWForDomainComparison = False
        # Ignore ssl warning loggers
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    # def main(self):
    #     pass

    def checkURL(self, domainCheckInfo: DomainCheckInfo):
        # mainDomain = domainCheckInfo.domains[0]
        progress = 1
        for domain in domainCheckInfo.domains:
            if len(domainCheckInfo.domains) > 1:
                print(f"Checking domain {progress} of {len(domainCheckInfo.domains)}: {domain}")
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
                domainCheckResult.problemType = ProblemType.NO_DNS_RECORD
                continue

            # Verbindungszeit testen
            start_time = time.time()
            try:
                # verify=False -> Ignore certificate warnings
                req = httpx.get("https://" + domain, timeout=self.timeout, verify=False, follow_redirects=True)
                html = req.text
                domainCheckResult.responsecode = req.status_code
                end_time = time.time()
                millisToConnectAndRead = end_time - start_time
                domainCheckResult.connectMillis = millisToConnectAndRead
                currentDomain = req.url.host
                # Redirect to a domain that differs from the one we know? Save that!
                if currentDomain != domain:
                    domainCheckResult.redirectedToDomain = currentDomain
                blockedBy = self.getBlockedBy(req)
                if blockedBy is not None:
                    domainCheckResult.problemType = ProblemType.BLOCKED_BY
                    domainCheckResult.blockedBy = blockedBy
                elif self.looksLikeParkedDomain(html):
                    domainCheckResult.problemType = ProblemType.PARKED_DOMAIN
            except ConnectTimeout:
                domainCheckResult.problemType = ProblemType.CONNECT_TIMEOUT
            except ReadTimeout:
                domainCheckResult.problemType = ProblemType.READ_TIMEOUT
            except ConnectError:
                domainCheckResult.problemType = ProblemType.WTF
            progress += 1

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
        lineNumber = 0
        for line in file:
            lineNumber += 1
            line = line.strip()
            if line == "":
                continue
            keywords = []
            if ' ' in line:
                url, keyword = line.split(" ", 1)  # die erste Leerzeichen-getrennte Zeichenkette als URL, den Rest als Keyword nehmen
                keywords = [keyword]
            else:
                url = line
            domain = regexDomain(url)
            # TODO: Make one check out of those two
            if domain is None or not isDomain(domain):
                print(f'Skipping line number {lineNumber} due to invalid domain: {domain} | Line content: {line}')
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
