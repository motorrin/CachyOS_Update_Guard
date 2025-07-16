#!/usr/bin/env python3
"""
Arch Linux & CachyOS Repository Monitor (Version 8.3 - Final Polished)
"""

import requests
import re
import time
import sys
import os
import random
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Set
import feedparser
import logging

# --- DATA CLASSES ---

@dataclass
class RepoIssue:
    """Represents a potential issue or failure found in a source."""
    source: str
    title: str
    description: str
    severity: str
    date: datetime
    url: str
    affected_packages: List[str]
    confidence_score: int
    semantic_groups: Set[str] = field(default_factory=set)


@dataclass
class PotentialFix:
    """Represents a post or news about a fix, patch, or positive update."""
    source: str
    title: str
    date: datetime
    url: str
    mentioned_packages: List[str]
    semantic_groups: Set[str] = field(default_factory=set)


@dataclass
class ResolvedIssue:
    """Represents an issue for which a probable solution has been found."""
    issue: RepoIssue
    fix: PotentialFix
    correlation_score: float


# --- MAIN MONITOR CLASS ---

class ArchRepoMonitor:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'ArchRepoMonitor/8.3'})
        self.min_confidence_threshold = 35

        # --- CENTRALIZED CONFIGURATION ---
        self.config = {
            'keywords': {
                'problem': [
                    'broken', 'break', 'fails', 'failure', 'error', 'bug', 'regression', 'downgrade',
                    'corrupt', 'crash', 'segfault', 'freeze', 'hangs', 'stalled', 'unstable',
                    'artifacting', 'stuttering', 'glitch', 'failed to start', 'doesn\'t launch', 'not working',
                    'issue', 'problematic', 'misbehaving', 'not starting', 'no longer works'
                ],
                'critical_boot_failure': [
                    'unable to boot', 'kernel panic', 'unbootable', 'system crash', 'no boot',
                    'black screen', 'data loss', 'corruption', 'bricked',
                    'disappear from bios', 'ssd disappear', 'nvme disappear', 'not detected in bios',
                    '/sbin/init does not exist', 'boot loop', 'stuck on boot', 'no display',
                    'no output', 'fails to boot', 'boot failure', 'bricked my'
                ],
                'kernel_failure_triggers': [
                    'module broken', 'modules broken', 'module fails', 'modules fail', 'modules are broken',
                    'kernel fails to build', 'kernel fails to load', 'kernel module broken'
                ],
                'help_indicators': [
                    'help me', 'can anyone help', 'my journalctl', 'dmesg log', 'my last boot log', 'what am i doing wrong',
                    'pastebin.com', '0x0.st', 'hastebin.com', 'termbin.com', 'my config is', 'my log', 'my logs',
                    'help', 'noob', 'newbie', 'new to arch', 'new to linux', 'how to', 'tutorial', 'guide', 'how do i',
                    'trying to', 'question about', 'can i'
                ],
                'debug_keywords': [
                    'journalctl', 'dmesg', 'pacman.log', 'backtrace', 'core dump', 'strace', 'bisect'
                ],
                'explicit_fix_markers': [
                    '[solved]', '(solved)', '[решено]', 'fs#', '[fix]', '[patched]', 'workaround for'
                ],
                'fix_keywords': [
                    'fix', 'fixed', 'patch', 'patched', 'workaround', 'resolved', 'solution'
                ],
                'strong_positive': [
                    'adds support', 'enables support', 'lands support', 'readies support', 'ships with',
                    'introduces', 'lands', 'merges', 'merged', 'enables', 'adds', 'release',
                    'improvement', 'improves', 'support for', 'is now on', 'is now available',
                    'has been released', 'announcing', 'released'
                ],
                'discussion': [
                    'why is', 'is it just me', 'what do you think', 'thoughts on', 'experience with',
                    'discussion', 'poll', 'review', 'switched to', 'journey', 'appreciation',
                    'dotfiles', 'love', 'amazing', 'enjoying', 'goodbye windows', 'finally happened',
                    'hello everyone', 'welcome to', 'showcase', 'my setup', 'my rice', 'post your',
                    'official thread', 'megathread', 'weekly thread', 'guide', 'tutorial', 'should i use'
                ],
                'user_space_apps': [
                    'steam', 'discord', 'lutris', 'heroic', 'blender', 'kdenlive', 'obs', 'vlc', 'firefox',
                    'thunderbird', 'game', 'elden ring', 'cyberpunk', 'wps-office', 'libreoffice', 'wine', 'proton'
                ],
                'semantic_groups': {
                    'storage': ['ssd', 'nvme', 'hdd', 'disk', 'btrfs', 'ext4', 'filesystem', 'mount', 'partition'],
                    'network': ['wifi', 'wi-fi', 'ethernet', 'network', 'connect', 'dhcp', 'dns', 'r8168', 'mt7922', 'bluetooth'],
                    'graphics': ['nvidia', 'amdgpu', 'intel', 'mesa', 'wayland', 'xorg', 'glitch', 'artifacting', 'tearing', 'hdr', 'compositor', 'display', 'monitor', 'resolution', 'hyprland', 'kde', 'gnome', 'plasma'],
                    'audio': ['pipewire', 'pulseaudio', 'alsa', 'sound', 'audio', 'speaker', 'headphone'],
                    'kernel': ['kernel', 'linux', 'module', 'dkms', 'panic', 'lts', 'zen', 'cachyos', 'init', 'ramdisk', 'suspend', 'wake'],
                    'boot': ['boot', 'grub', 'systemd-boot', 'uefi', 'bios', 'mkinitcpio', 'bricked'],
                    'system': ['systemd', 'glibc', 'pacman', 'dbus', 'base']
                }
            },
            'packages': {
                'weights': {
                    'glibc': 1.8, 'grub': 1.8, 'systemd': 1.6, 'linux': 1.5, 'linux-lts': 1.5,
                    'linux-zen': 1.5, 'linux-hardened': 1.5, 'pacman': 1.5, 'mkinitcpio': 1.2,
                    'base': 1.1, 'filesystem': 1.3, 'dbus': 1.1, 'linux-cachyos': 1.7,
                    'cachyos-settings': 1.3, 'cachy-sched': 1.4, 'bore-sched': 1.4,
                    'cachyos-ananicy-rules-git': 1.2, 'cachyos-grub-theme': 1.0, 'cachyos-hooks': 1.1,
                    'mesa': 1.4, 'nvidia': 1.4, 'nvidia-dkms': 1.4, 'amdgpu': 1.3,
                    'wayland': 1.2, 'xorg-server': 1.2, 'plasma': 1.1, 'pipewire': 1.1, 'default': 1.0
                },
                'categories': {
                    'kernel_packages': ['linux', 'linux-lts', 'linux-zen', 'linux-hardened', 'linux-cachyos'],
                    'critical_system': ['systemd', 'glibc', 'grub', 'pacman', 'filesystem', 'base', 'mkinitcpio'],
                    'critical_cachyos': ['cachy-sched', 'bore-sched'],
                    'important': ['mesa', 'nvidia', 'nvidia-dkms', 'amdgpu', 'wayland', 'pipewire', 'plasma']
                }
            },
            'sources': {
                'cachyos_news': 'https://cachyos.org/blog/index.xml',
                'cachyos_kernel_repo': 'https://api.github.com/repos/CachyOS/linux-cachyos/issues?state=all&sort=created&direction=desc',
                'arch_news': 'https://archlinux.org/feeds/news/',
                'arch_bugs': 'https://bugs.archlinux.org/index.php?string=&project=1&type%5B%5D=1&sev%5B%5D=5&sev%5B%5D=4&sev%5B%5D=3&due%5B%5D=3&cat%5B%5D=3&reported%5B%5D=14&opened=&due=&closed=&updated=&dev=&do=index&action=do_search&order=dateopened&sort=desc&format=rss',
                'arch_reddit': 'https://www.reddit.com/r/archlinux/new.json?limit=50',
                'arch_forums_recent': 'https://bbs.archlinux.org/extern.php?action=feed&type=rss',
                'phoronix': 'https://www.phoronix.com/rss.php',
            },
            'weights': {
                'source': {
                    'Arch Linux News': 2.0, 'Arch Linux Bugs': 1.8, 'CachyOS Blog': 1.9,
                    'Arch Linux Security': 2.2, 'CachyOS Kernel Issues': 2.1, 'Phoronix': 0.85,
                    'Reddit r/archlinux': 0.8, 'Arch Forums': 0.7
                },
                'severity': {'critical': 50, 'high': 25, 'medium': 10, 'low': 0}
            },
            'source_types': {
                'official': ['Arch Linux News', 'Arch Linux Bugs', 'CachyOS Blog', 'CachyOS Kernel Issues', 'Arch Linux Security'],
                'community': ['Reddit r/archlinux', 'Arch Forums', 'Phoronix']
            }
        }

        self.all_known_packages = list(self.config['packages']['weights'].keys())
        # Create a master list of stop words for cleaning package names
        self.master_stop_list = {'a', 'an', 'the', 'it', 'is', 'to', 'for', 'in', 'on', 'with', 'and', 'or', 'if', 'using',
                                 'my', 'me', 'from', 'format', 'then', 'that', 'this', 'after', 'before', 'you',
                                 'main', 'core', 'extra', 'testing', 'cachyos', 'so'}
        for category, keywords in self.config['keywords'].items():
            self.master_stop_list.update(keywords)
        # Additional list to filter out "noisy" words
        self.common_word_stoppers = {'etc', 'but', 'needs', 'both', 'top', 'honor', 'layers', 'decrypted', 'some', 'of'}

    def _get_severity(self, text: str, title: str, source: str) -> Tuple[str, str]:
        """Determines severity using a hierarchy of priority rules and the source."""
        final_severity, reason = 'low', 'No explicit issues found.'

        boot_failure_keyword = next((k for k in self.config['keywords']['critical_boot_failure'] if k in text), None)
        if boot_failure_keyword:
            if source in self.config['source_types']['community']:
                final_severity, reason = 'high', f"Found a phrase indicating a serious issue: '{boot_failure_keyword}'. Source is community."
            else:
                final_severity, reason = 'critical', f"Found a critical phrase in an official source: '{boot_failure_keyword}'."
            is_critical = True
        else:
            is_critical = False

        mentioned_packages = self._extract_packages(text)
        is_kernel_related = any(p in mentioned_packages for p in self.config['packages']['categories']['kernel_packages'])
        kernel_failure_keyword = next((k for k in self.config['keywords']['kernel_failure_triggers'] if k in text), None)

        if not is_critical and is_kernel_related and kernel_failure_keyword:
            final_severity, reason = 'critical', f"Kernel module failure detected: '{kernel_failure_keyword}'"
            is_critical = True

        has_problem = any(k in text for k in self.config['keywords']['problem'])
        if not has_problem and not is_critical:
            return 'low', 'No problem-related keywords found.'

        if not is_critical:
            pkg_cat = self.config['packages']['categories']
            has_critical_system = any(p in mentioned_packages for p in pkg_cat['critical_system'])
            has_cachyos_pkg = any(p in mentioned_packages for p in pkg_cat['critical_cachyos'])
            has_important = any(p in mentioned_packages for p in pkg_cat['important'])

            if has_critical_system or has_cachyos_pkg or (is_kernel_related and has_problem):
                final_severity, reason = 'high', 'Affects a critical system package or kernel.'
            elif has_important:
                final_severity, reason = 'medium', 'Affects an important (non-system) package.'
            elif has_problem:
                 final_severity, reason = 'low', 'A problem keyword was found, but not related to important packages.'

        is_app_specific_problem = any(app in text for app in self.config['keywords']['user_space_apps'])
        if final_severity in ['high', 'medium'] and is_app_specific_problem:
            is_critical_involved = any(p in mentioned_packages for p in self.config['packages']['categories']['critical_system'])
            if not is_critical_involved:
                app_name = next((app for app in self.config['keywords']['user_space_apps'] if app in text), "app")
                new_sev = 'medium' if final_severity == 'high' else 'low'
                reason = f"Severity downgraded to '{new_sev}'; the issue is likely related to the application '{app_name}' rather than a system component."
                final_severity = new_sev

        is_help_request = any(k in text for k in self.config['keywords']['help_indicators'])
        if is_help_request and not is_critical:
            if final_severity == 'high':
                final_severity = 'medium'
                reason += " (Post appears to be a help request, but the issue is still serious)."
            elif final_severity == 'medium':
                final_severity = 'low'
                reason = "Severity downgraded to 'low'; post appears to be a help request."

        return (final_severity, reason)

    def _get_semantic_groups(self, text: str) -> Set[str]:
        """Determines the semantic groups to which the text belongs."""
        text_lower = text.lower()
        return {group for group, keywords in self.config['keywords']['semantic_groups'].items() if any(k in text_lower for k in keywords)}

    def _extract_packages(self, text: str) -> List[str]:
        """Extracts potential package names from the text."""
        text = text.lower()
        known_packages = {pkg for pkg in self.all_known_packages if re.search(r'\b' + re.escape(pkg) + r'\b', text)}
        
        potential_packages = set(re.findall(
            r'(?:package|updating|installing|downgrade|fails with|issue with|problem with|after updating|update of|update to|on)\s+([a-z0-9][a-z0-9\.\-_]+)',
            text
        ))
        
        more_potential = set(re.findall(r'\b([a-z-]{3,}-git|[a-z]{3,}-dkms|[a-z]{2,}hd)\b', text))
        
        cleaned_potential = {pkg.strip('.,:;!?()[]{}') for pkg in potential_packages.union(more_potential)}
        # Use both stop word lists for maximum cleaning
        filtered_packages = {pkg for pkg in cleaned_potential if pkg not in self.master_stop_list and pkg not in self.common_word_stoppers and not pkg.isdigit()}
        
        final_packages = known_packages.union(filtered_packages)
        return list(final_packages)

    def _is_potential_fix(self, title: str, full_text: str) -> bool:
        """Determines if a post is a likely fix using strict criteria."""
        if any(marker in title for marker in self.config['keywords']['explicit_fix_markers']):
            return True
        if any(keyword in full_text for keyword in self.config['keywords']['fix_keywords']):
            return True
        return False

    def _process_entry(self, name: str, title: str, full_content: str, date: datetime, url: str, base_confidence: int) -> Tuple[Optional[RepoIssue], Optional[PotentialFix]]:
        """Processes a single entry, performing analysis on the full text."""
        lower_title, full_text = title.lower(), (title.lower() + ' ' + full_content.lower())
        logging.debug(f"  [ANALYZING] '{title}'")

        packages = self._extract_packages(full_text)
        semantic_groups = self._get_semantic_groups(full_text)

        if self._is_potential_fix(lower_title, full_text):
            return None, PotentialFix(name, title, date, url, packages, semantic_groups)

        if any(k in full_text for k in self.config['keywords']['strong_positive']):
            logging.debug("    -> Ignoring (new feature or announcement).")
            return None, None
        
        if any(k in full_text for k in self.config['keywords']['discussion']):
            logging.debug("    -> Ignoring (discussion).")
            return None, None

        severity, reason = self._get_severity(full_text, title, name)
        if severity != 'low':
            confidence = base_confidence
            if any(k in full_text for k in self.config['keywords']['debug_keywords']):
                confidence = min(100, confidence + 15)
                reason += " (Confidence increased due to the presence of debug information)."
            
            logging.debug(f"    -> OK: Severity '{severity}'. Reason: {reason}. Confidence {confidence}%.")
            issue = RepoIssue(name, title, full_content[:300] + '...', severity, date, url, packages, confidence, semantic_groups)
            return issue, None

        return None, None

    def _fetch_feed(self, name: str, url: str, confidence: int, days_limit: int = 7) -> Tuple[List[RepoIssue], List[PotentialFix]]:
        """Fetches and analyzes an RSS/Atom feed."""
        issues, fixes = [], []
        logging.debug(f"--- Source (Feed): {name} ---")
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries:
                pub_date = datetime(*entry.get('published_parsed', time.gmtime())[:6])
                if (datetime.now() - pub_date).days > days_limit: continue
                
                issue, fix = self._process_entry(
                    name, entry.title, entry.get('summary', ''), pub_date, entry.link, confidence
                )
                if issue: issues.append(issue)
                if fix: fixes.append(fix)
        except Exception as e:
            logging.error(f"Error fetching data from {name}: {e}")
        return issues, fixes

    def fetch_reddit(self, name: str, url: str) -> Tuple[List[RepoIssue], List[PotentialFix]]:
        """Fetches and analyzes Reddit posts."""
        issues, fixes = [], []
        logging.debug(f"--- Source (Reddit): {name} ---")
        try:
            response = self.session.get(url)
            response.raise_for_status()
            for post in response.json()['data']['children']:
                post_data = post['data']
                score, num_comments = post_data.get('score', 0), post_data.get('num_comments', 0)
                
                is_potentially_critical = any(k in post_data.get('title', '').lower() for k in self.config['keywords']['critical_boot_failure'])
                if not is_potentially_critical and (score < 2 and num_comments < 2):
                    continue

                created_time = datetime.fromtimestamp(post_data['created_utc'])
                if created_time < datetime.now() - timedelta(days=3): continue
                
                base_confidence = min(100, 30 + (score * 4) + (num_comments * 2))

                issue, fix = self._process_entry(
                    name, post_data['title'], post_data.get('selftext', ''), created_time,
                    f"https://reddit.com{post_data['permalink']}", base_confidence
                )
                if issue: issues.append(issue)
                if fix: fixes.append(fix)
        except Exception as e:
            logging.error(f"Error fetching data from {name}: {e}")
        return issues, fixes

    def fetch_github_issues(self, name: str, url: str) -> Tuple[List[RepoIssue], List[PotentialFix]]:
        """Fetches and analyzes GitHub issues, using labels for accuracy."""
        issues, fixes = [], []
        logging.debug(f"--- Source (GitHub): {name} ---")
        try:
            response = self.session.get(url)
            response.raise_for_status()
            for issue_data in response.json()[:30]:
                created_date = datetime.strptime(issue_data['created_at'], '%Y-%m-%dT%H:%M:%SZ')
                if (datetime.now() - created_date).days > 21: continue

                title, body = issue_data['title'], issue_data.get('body', '') or ''
                full_text = title + ' ' + body
                packages = self._extract_packages(full_text)
                semantic_groups = self._get_semantic_groups(full_text)
                
                is_closed = issue_data.get('state') == 'closed'
                if is_closed:
                    fixes.append(PotentialFix(name, title, created_date, issue_data['html_url'], packages, semantic_groups))
                    continue

                base_confidence = min(95, 80 + (issue_data.get('comments', 0) * 3))

                issue, _ = self._process_entry(
                    name, title, body, created_date, issue_data['html_url'], base_confidence
                )
                
                if issue:
                    issue.affected_packages = packages
                    issue.semantic_groups = semantic_groups
                    
                    labels = {label['name'].lower() for label in issue_data.get('labels', [])}
                    if 'critical' in labels or 'regression' in labels:
                        issue.severity, issue.confidence_score = 'critical', 100
                    elif 'bug' in labels and issue.severity != 'critical':
                        issue.severity, issue.confidence_score = 'high', 100
                    issues.append(issue)
        except Exception as e:
            logging.error(f"Error fetching GitHub Issues from {name}: {e}")
        return issues, fixes
        
    def _get_title_similarity(self, title1: str, title2: str) -> float:
        """Calculates title similarity using the Jaccard index."""
        words1 = set(re.sub(r'[^\w\s]', '', title1.lower()).split())
        words2 = set(re.sub(r'[^\w\s]', '', title2.lower()).split())
        if not words1 or not words2: return 0.0
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        return intersection / union

    def _deduplicate(self, items: List) -> List:
        """Removes duplicates based on title similarity."""
        unique_items, seen_titles = [], []
        if not items: return []

        is_issue = isinstance(items[0], RepoIssue)
        sort_key = (lambda x: x.confidence_score) if is_issue else (lambda x: x.date)
        items.sort(key=sort_key, reverse=True)

        for item in items:
            is_duplicate = any(self._get_title_similarity(item.title, seen_title) > 0.7 for seen_title in seen_titles)
            if not is_duplicate:
                unique_items.append(item)
                seen_titles.append(item.title)
        return unique_items

    def _calculate_correlation_score(self, issue: RepoIssue, fix: PotentialFix) -> float:
        """Calculates a weighted similarity score between an issue and a fix."""
        # 1. Title similarity (weight: 50%)
        title_sim = self._get_title_similarity(issue.title, fix.title)

        # 2. Package intersection (weight: 30%)
        issue_pkgs = set(issue.affected_packages)
        fix_pkgs = set(fix.mentioned_packages)
        pkg_overlap_score = 0.0
        if issue_pkgs and fix_pkgs:
            overlap = len(issue_pkgs & fix_pkgs)
            if any(p in (issue_pkgs & fix_pkgs) for p in self.config['packages']['weights']):
                overlap += 1
            pkg_overlap_score = min(1.0, overlap * 0.5)

        # 3. Contextual compatibility (weight: 20%)
        context_modifier = 0.0
        intersection = issue.semantic_groups & fix.semantic_groups
        if intersection:
            context_modifier = 0.5 + (len(intersection) * 0.25) # Bonus for intersection
        elif 'kernel' in fix.semantic_groups or 'system' in fix.semantic_groups:
             context_modifier = 0.25 
        elif issue.semantic_groups and fix.semantic_groups:
             context_modifier = -0.5 # Penalty for clear mismatch
        
        score = (title_sim * 0.5) + (pkg_overlap_score * 0.3) + (context_modifier * 0.2)
        return max(0, min(1.0, score))

    def _correlate_and_filter(self, issues: List[RepoIssue], fixes: List[PotentialFix]) -> Tuple[List[RepoIssue], List[ResolvedIssue]]:
        """Correlates issues with fixes using a weighted score."""
        unresolved_issues = []
        resolved_issues = []
        used_fix_urls = set()
        correlation_threshold = 0.65 # Final, increased threshold for reliability

        for issue in sorted(issues, key=lambda i: i.date):
            best_match_fix = None
            highest_score = correlation_threshold 

            issue_id_match = re.search(r'(?:FS#|issues/|task_id=|id=)(\d+)', issue.url)
            issue_id = issue_id_match.group(1) if issue_id_match else None

            for fix in sorted(fixes, key=lambda f: f.date):
                if fix.date < issue.date or fix.url in used_fix_urls:
                    continue
                
                final_score = 0.0
                if issue_id and (re.search(f'(?:fixes |resolves |closes |FS#|#){issue_id}\\b', fix.title, re.IGNORECASE) or issue_id in fix.url):
                    final_score = 1.0 
                else:
                    final_score = self._calculate_correlation_score(issue, fix)
                
                logging.debug(
                    f"  [CORRELATE] Issue: '{issue.title[:30]}...' | Fix: '{fix.title[:30]}...' | Score: {final_score:.2f}"
                )
                
                if final_score > highest_score:
                    highest_score = final_score
                    best_match_fix = fix

            if best_match_fix:
                logging.info(f"Match found for '{issue.title[:40]}...': Fix '{best_match_fix.title[:40]}...' (Score: {highest_score:.2f})")
                resolved_issues.append(ResolvedIssue(issue=issue, fix=best_match_fix, correlation_score=highest_score))
                used_fix_urls.add(best_match_fix.url)
            else:
                unresolved_issues.append(issue)

        return unresolved_issues, resolved_issues

    def check_repo_status(self) -> Dict:
        """Main orchestrator function to collect, analyze, and compile report data."""
        logging.info(f"Starting repository status check (v8.3)...")
        all_issues_raw, all_fixes_raw = [], []

        def process_fetch(fetch_result):
            issues, fixes = fetch_result
            all_issues_raw.extend(issues)
            all_fixes_raw.extend(fixes)

        process_fetch(self._fetch_feed('Arch Linux News', self.config['sources']['arch_news'], 95))
        process_fetch(self._fetch_feed('Arch Linux Bugs', self.config['sources']['arch_bugs'], 98, days_limit=14))
        process_fetch(self.fetch_reddit('Reddit r/archlinux', self.config['sources']['arch_reddit']))
        process_fetch(self._fetch_feed('Phoronix', self.config['sources']['phoronix'], 70))
        process_fetch(self._fetch_feed('Arch Forums', self.config['sources']['arch_forums_recent'], 75))
        process_fetch(self._fetch_feed('CachyOS Blog', self.config['sources']['cachyos_news'], 95))
        process_fetch(self.fetch_github_issues('CachyOS Kernel Issues', self.config['sources']['cachyos_kernel_repo']))

        logging.info(f"Collected {len(all_issues_raw)} potential issues and {len(all_fixes_raw)} potential fixes. Filtering...")

        confident_issues = [i for i in all_issues_raw if i.confidence_score >= self.min_confidence_threshold]
        dedup_issues = self._deduplicate(confident_issues)
        dedup_fixes = self._deduplicate(all_fixes_raw)

        logging.info(f"After deduplication: {len(dedup_issues)} issues and {len(dedup_fixes)} fixes. Correlating...")
        unresolved, resolved = self._correlate_and_filter(dedup_issues, dedup_fixes)

        logging.info(f"After correlation: {len(unresolved)} unresolved issues, {len(resolved)} resolved.")

        unresolved.sort(key=lambda i: (self.config['weights']['severity'].get(i.severity, 0) + i.confidence_score), reverse=True)

        safety_status = self._analyze_update_safety(unresolved)

        return {
            'timestamp': datetime.now(),
            'unresolved_issues': unresolved,
            'resolved_issues': resolved,
            'fixes': dedup_fixes,
            'safety_status': safety_status,
            'recommendation': self._get_recommendation(safety_status),
            'sources_checked': len(self.config['sources'])
        }

    def _analyze_update_safety(self, issues: List[RepoIssue]) -> Dict:
        """Calculates a 'danger score' based on the list of unresolved issues."""
        danger_score, critical_issues_count, high_issues_count = 0, 0, 0
        affected_critical_packages = set()

        logging.debug("--- Calculating danger score for unresolved issues ---")
        for issue in issues:
            base_score = self.config['weights']['severity'].get(issue.severity, 0)
            source_weight = self.config['weights']['source'].get(issue.source, 1.0)

            pkg_weights = self.config['packages']['weights']
            max_pkg_weight = max([pkg_weights.get(p, 1.0) for p in issue.affected_packages] or [1.0])

            is_app_specific = any(app in (issue.title.lower() + issue.description.lower()) for app in self.config['keywords']['user_space_apps'])
            is_critical_involved = any(p in issue.affected_packages for p in self.config['packages']['categories']['critical_system'])
            
            if is_app_specific and not is_critical_involved and issue.severity != 'critical':
                original_weight = max_pkg_weight
                max_pkg_weight = (max_pkg_weight + 1.0) / 2
                logging.debug(f"  -> Adjusted weight for application-specific issue '{issue.title[:20]}...'. Weight changed from {original_weight:.2f} to {max_pkg_weight:.2f}")

            time_decay = 0.92 ** ((datetime.now() - issue.date).total_seconds() / 86400.0)
            issue_danger = base_score * source_weight * (issue.confidence_score / 100.0) * time_decay * max_pkg_weight
            danger_score += issue_danger
            logging.debug(f"  '{issue.title[:40]}...' adds {issue_danger:.2f} points (severity: {issue.severity}, package weight: {max_pkg_weight:.2f})")

            if issue.severity == 'critical': critical_issues_count += 1
            if issue.severity == 'high': high_issues_count += 1
            if issue.severity in ['critical', 'high']:
                affected_critical_packages.update(p for p in issue.affected_packages if p in self.config['packages']['weights'])

        level = 'SAFE'
        if danger_score > 100: level = 'DANGEROUS'
        elif danger_score > 55: level = 'RISKY'
        elif danger_score > 25: level = 'CAUTION'

        logging.info(f"Final danger score: {round(danger_score)}. Safety level: {level}.")
        return {
            'level': level, 'danger_score': round(danger_score),
            'critical_issues': critical_issues_count, 'high_issues': high_issues_count,
            'affected_critical_packages': list(affected_critical_packages)
        }

    def _get_recommendation(self, safety_status: Dict) -> str:
        """Generates a recommendation based on the safety status."""
        level = safety_status['level']
        if level == 'DANGEROUS': return "❌ DO NOT UPDATE! Confirmed critical or numerous serious issues have been detected."
        if level == 'RISKY': return "⚠️ UPDATE NOT RECOMMENDED. Serious risks have been identified. Review the report carefully."
        if level == 'CAUTION': return "🟡 UPDATE WITH CAUTION. There are reports of issues. Ensure you have backups."
        return "✅ UPDATE IS LIKELY SAFE. No significant unresolved issues were found."

    def generate_report(self) -> str:
        """Generates the final, formatted text report."""
        status = self.check_repo_status()
        unresolved_issues = status['unresolved_issues']
        official_issues = [i for i in unresolved_issues if i.source in self.config['source_types']['official']]
        community_issues = [i for i in unresolved_issues if i.source in self.config['source_types']['community']]
        severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '⚪️'}
        
        report_title = "PROACTIVE ARCH & CACHYOS REPOSITORY ANALYSIS (v8.3)"

        report = f"""
╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                     {report_title:<133}║
╠══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣
║ Check Time: {status['timestamp'].strftime('%Y-%m-%d %H:%M:%S'):<20}| Sources Analyzed: {status['sources_checked']:<92}║
║ Safety Level: {status['safety_status']['level']:<10} (Danger Score: {status['safety_status']['danger_score']:<99})║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
🎯 RECOMMENDATION: {status['recommendation']}
📊 RISK OVERVIEW (based on unresolved issues):
   • Critical Issues: {status['safety_status']['critical_issues']}
   • High-Severity Issues: {status['safety_status']['high_issues']}
   • Affected Critical Packages: {', '.join(sorted(status['safety_status']['affected_critical_packages'])) or 'None'}
"""
        if unresolved_issues:
            report += "\n" + "─" * 80
            report += "\n❗️ UNRESOLVED ISSUES REQUIRING ATTENTION\n"

            if official_issues:
                report += f"\n📌 Official & Confirmed ({len(official_issues)}):\n"
                for i, issue in enumerate(official_issues[:5], 1):
                    report += f"\n{i}. {severity_emoji.get(issue.severity, '⚪️')} [{issue.severity.upper()}] {issue.title}\n"
                    report += f"   📅 {issue.date.strftime('%Y-%m-%d')} | 📰 {issue.source} | 📈 Confidence: {issue.confidence_score}%\n"
                    if issue.affected_packages: report += f"   📦 Packages: {', '.join(sorted(issue.affected_packages))}\n"
                    report += f"   🔗 {issue.url}"

            if community_issues:
                report += f"\n\n🗣️ Community Reports ({len(community_issues)}):\n"
                for i, issue in enumerate(community_issues[:5], 1):
                    report += f"\n{i}. {severity_emoji.get(issue.severity, '⚪️')} [{issue.severity.upper()}] {issue.title}\n"
                    report += f"   📅 {issue.date.strftime('%Y-%m-%d')} | 📰 {issue.source} | 📈 Confidence: {issue.confidence_score}%\n"
                    if issue.affected_packages: report += f"   📦 Packages: {', '.join(sorted(issue.affected_packages))}\n"
                    report += f"   🔗 {issue.url}"
        else:
            report += "\n\n✅ No active issues requiring attention were found."

        if status['resolved_issues']:
            report += "\n\n" + "─" * 80
            report += f"\n✅ RESOLVED ISSUES ({len(status['resolved_issues'])} matches found)\n"
            for i, res_issue in enumerate(status['resolved_issues'][:5], 1):
                score_percent = int(res_issue.correlation_score * 100)
                report += f"\n{i}. [ISSUE] {res_issue.issue.title}\n"
                report += f"   [FIX (Correlation: {score_percent}%)] {res_issue.fix.title}\n"
                report += f"   🔗 {res_issue.fix.url}"

        report += """

💡 ADVICE:
   • This script is an advisory tool. Always make your own informed decisions.
   • Before any major update (`pacman -Syu`), always check the news on `archlinux.org`.
   • Use `timeshift` or another snapshot system for easy rollbacks.
🔄 To run the check again, execute the script. (For detailed debug output, run with the --verbose flag)
"""
        return report

# --- SCRIPT EXECUTION ---

def main():
    """Main function to set up logging and run the monitor."""
    MAX_LOG_FILES = 30
    script_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in locals() else os.getcwd()
    log_dir = os.path.join(script_dir, "arch_monitor_runs")
    os.makedirs(log_dir, exist_ok=True)

    is_verbose = '--verbose' in sys.argv
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    console_level = logging.INFO
    if not is_verbose:
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        class InfoFilter(logging.Filter):
            def filter(self, record):
                return record.levelno >= logging.INFO
        console_handler.addFilter(InfoFilter())
    else: 
        console_level = logging.DEBUG
        console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    console_handler.setLevel(console_level)
    root_logger.addHandler(console_handler)

    try:
        all_files = [os.path.join(log_dir, f) for f in os.listdir(log_dir) if f.endswith('.log')]
        if len(all_files) >= MAX_LOG_FILES:
            oldest_file = min(all_files, key=os.path.getmtime)
            os.remove(oldest_file)
            logging.info(f"Log limit reached. Deleting the oldest file: {os.path.basename(oldest_file)}")
    except Exception as e:
        logging.error(f"An error occurred during log rotation: {e}")

    run_id = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{random.randint(10000, 99999)}"
    log_file_path = os.path.join(log_dir, f"run_{run_id}.log")
    file_handler = logging.FileHandler(log_file_path, mode='w', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    root_logger.addHandler(file_handler)
    
    file_handler.stream.write(f"INFO: 🔍 Arch Linux & CachyOS Comprehensive Monitor v8.3 (Final Polished)\n" + "="*60 + "\n")
    file_handler.stream.write(f"INFO: Run ID: {run_id}\n")

    try:
        monitor = ArchRepoMonitor()
        report_text = monitor.generate_report()
        sys.stdout.write(report_text)
        
        logging.debug("\n\n" + "="*80 + "\n          FULL REPORT (saved to log)\n" + "="*80)
        logging.debug(report_text)
        # Log only the file save message to INFO, the report itself is already in DEBUG
        logging.info("="*80 + f"\n\n📄 Detailed log and report saved to a single file: {log_file_path}")

    except KeyboardInterrupt:
        logging.warning("\n\n❌ Check interrupted by user.")
    except Exception as e:
        logging.critical(f"A critical error occurred in the script: {e}", exc_info=True)

if __name__ == "__main__":
    main()
