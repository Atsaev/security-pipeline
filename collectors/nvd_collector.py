from urllib import response

import httpx
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv

from models.cve import CVEModel


load_dotenv()

NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
NVD_API_KEY = os.getenv('NVD_TOKEN')

class NVDCollector:
    def __init__(self):
        api_key = NVD_API_KEY
        self.headers = {'api_key': api_key}

    def _parse_item(self, item: dict) -> CVEModel | None:
        try:
            cve_data = item['cve']
            description = next(
                (d['value']for d in cve_data['descriptions'] if d['lang'] ==
                 'en'),
                'Не найдено'
            )
            cvss_score = None
            severity = None
            metrics = cve_data.get('metrics', {})

            if 'cvssMetricV31' in metrics:
                cvss = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss['baseScore']
                severity = cvss['baseSeverity']
            elif 'cvssMetricV2' in metrics:
                cvss = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss['baseScore']
                severity = metrics['cvssMetricV2'][0].get('baseSeverity')

            products = []
            for config in cve_data.get('configurations', []):
                for node in config.get('nodes', []):
                    for match in node.get('cpeMatch', []):
                        products.append(match['criteria'])
            return CVEModel(
                cve_id=cve_data['id'],
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                published_date=cve_data['published'],
                last_modified=cve_data['lastModified'],
                affected_products=products[:10],
                references=[r['url'] for r in cve_data.get('references',
                                                           [])[:5] ],

            )
        except Exception as e:
            print(f"  Ошибка парсинга: {e}")
            return None


    def fetch_recent(self, days: int = 30) -> list[CVEModel]:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)

        params = {
            'pubStartDate': start.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'resultsPerPage': 20,
        }

        print('Запрос к NVD API ...')
        print(f"  Период: {params['pubStartDate']} → {params['pubEndDate']}")
        response = httpx.get(NVD_API_URL, params=params,
                             headers=self.headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        total = data.get('totalResults', 0)
        print(f' Всего найдено в API: {total}')

        cves = []
        for item in data.get('vulnerabilities', []):
            cve = self._parse_item(item)
            if cve:
                cves.append(cve)
        return cves


