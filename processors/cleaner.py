from collections import Counter
from models.cve import CVEModel

class CVECleaner:
    def clean(self, cves: list[CVEModel]) -> list[CVEModel]:
        cleaned = []
        for cve in cves:
            cve = self._fix_description(cve)
            cve = self._fix_severity(cve)
            if self._is_valid(cve):
                cleaned.append(cve)

        print(f' До чистки: {len(cves)}')
        print(f' После чистки: {len(cleaned)}')
        return cleaned

    def get_stats(self, cves: list[CVEModel]) -> dict:
        severity_counts = Counter(c.severity or 'UNKNOWN' for c in cves)
        scores = [c.cvss_score for c in cves if c.cvss_score is not None]

        return {
            'Всего': len(cves),
            'По ур опасности': dict(severity_counts.most_common()),
            'Средний балл': round(sum(scores) / len(cves), 2) if scores
            else 0.0,
            'Максимальный балл': max(scores) if scores else 0.0,
        }

    def _fix_description(self, cve: CVEModel) -> CVEModel:
        if len(cve.description) > 500:
            cve = cve.model_copy(update={'description': cve.description[
                :500] + '...'})
        return cve

    def _fix_severity(self, cve: CVEModel) -> CVEModel:
        if cve.severity is None and cve.cvss_score is not None:
            if cve.cvss_score >= 9.0:
                severity = 'CRITICAL'
            elif cve.cvss_score >= 7.0:
                severity = 'HIGH'
            elif cve.cvss_score >= 4.0:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            cve = cve.model_copy(update={'severity': severity})
        return cve

    def _is_valid(self, cve: CVEModel) -> bool:
        if not cve.cve_id or not cve.description:
            return False
        if cve.description == 'No description':
            return False
        return True