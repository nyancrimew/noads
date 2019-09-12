# based on https://github.com/DandelionSprout/adfilt/blob/master/AdGuard Home Compilation List/AGHtest.py
import requests
import re
import datetime
from collections import OrderedDict 

DEBUG = False

LOCAL_SOURCES = [
    'lists/fo-scumware.txt',
    'lists/additional-rules.txt',
    'lists/add-switzerland.txt',
    'lists/unbreak.txt',
    'lists/yt-ads.txt'
]

SOURCES = [
    'https://1hos.cf/complete.',
    'https://280blocker.net/files/280blocker_domain.txt',
    'https://adaway.org/hosts.txt',
    'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
    'https://easylist-downloads.adblockplus.org/easylistchina.txt',
    'https://easylist.to/easylist/easyprivacy.txt',
    'https://gist.githubusercontent.com/BBcan177/2a9fc2548c3c5a5e2dc86e580b5795d2/raw/2f5c90ffb3bd02199ace1b16a0bd9f53b29f0879/EasyList_DE',
    'https://gitlab.com/curben/urlhaus-filter/raw/master/urlhaus-filter-online.txt',
    'https://hosts-file.net/ad_servers.txt',
    'https://hosts-file.net/mmt.txt',
    'https://hosts-file.net/pup.txt',
    'https://hosts.nfz.moe/full/hosts',
    'https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt',
    'https://raw.githubusercontent.com/Akamaru/Pi-Hole-Lists/master/fakenewsde.txt',
    'https://raw.githubusercontent.com/anudeepND/youtubeadsblacklist/master/domainlist.txt',
    'https://raw.githubusercontent.com/bcye/Hello-Goodbye/master/filterlist.txt',
    'https://raw.githubusercontent.com/cbuijs/shallalist/master/costtraps/domains',
    'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt',
    'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/AdGuard%20Home%20Compilation%20List/AdGuardHomeCompilationList.txt',
    'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/AntiPreacherList.txt',
    'https://raw.githubusercontent.com/deathbybandaid/piholeparser/master/Subscribable-Lists/ParsedBlacklists/EasyList-Liste-FR.txt',
    'https://raw.githubusercontent.com/deathbybandaid/piholeparser/master/Subscribable-Lists/ParsedBlacklists/EasyList-Thailand.txt',
    'https://raw.githubusercontent.com/deathbybandaid/piholeparser/master/Subscribable-Lists/ParsedBlacklists/Filtros-Nauscopicos.txt',
    'https://raw.githubusercontent.com/easylistbrasil/easylistbrasil/filtro/easylistbrasil.txt',
    'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts',
    'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts',
    'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts',
    'https://raw.githubusercontent.com/hell-sh/Evil-Domains/master/evil-domains.txt',
    'https://raw.githubusercontent.com/HenningVanRaumle/pihole-ytadblock/master/ytadblock.txt',
    'https://raw.githubusercontent.com/jakejarvis/ios-trackers/master/blocklist.txt',
    'https://raw.githubusercontent.com/jwinnie/acceptable-ads/master/filters.txt',
    'https://raw.githubusercontent.com/marktron/fakenews/master/fakenews',
    'https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts',
    'https://raw.githubusercontent.com/miyurusankalpa/adblock-list-sri-lanka/master/lkfilter.txt',
    'https://raw.githubusercontent.com/mtxadmin/ublock/master/hosts.txt',
    'https://raw.githubusercontent.com/ookangzheng/blahdns/master/hosts/blacklist.txt',
    'https://raw.githubusercontent.com/ookangzheng/blahdns/master/hosts/contentfarms.host',
    'https://raw.githubusercontent.com/pirat28/IHateTracker/master/iHateTracker.txt',
    'https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt',
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts',
    'https://raw.githubusercontent.com/UnluckyLuke/BlockUnderRadarJunk/master/blockunderradarjunk-list.txt',
    'https://raw.githubusercontent.com/w13d/adblockListABP-PiHole/master/list.txt',
    'https://raw.githubusercontent.com/xxcriticxx/.pl-host-file/master/hosts.txt',
    'https://sites.google.com/site/cosmonoteshosts/hosts_Ultimate.txt',
    'https://ssl.bblck.me/blacklists/hosts-file.txt',
    'https://v.firebog.net/hosts/Easylist.txt',
    'https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt'
]

UNSUPPORTED_AGH = [
    '##',
    '@#',
    '#?#',
    'domain=',
    'generichide',
    '$csp',
    'badfilter',
    'xmlhttprequest',
    '$xhr',
    '$stylesheet',
    '~image',
    '$elemhide',
    '$inline-script',
    '$other',
    '$~object',
    'redirect='
]

FORBIDDEN_LINES = [
    r'^localhost( |$)',
    r'^localhost.localdomain( |$)',
    r'^local( |$)',
    r'^broadcasthost( |$)',
    r'^localhost( |$)',
    r'^ip6-localhost( |$)',
    r'^ip6-loopback( |$)',
    r'^localhost( |$)',
    r'^ip6-localnet( |$)',
    r'^ip6-mcastprefix( |$)',
    r'^ip6-allnodes( |$)',
    r'^ip6-allrouters( |$)',
    r'^ip6-allhosts( |$)',
    r'^0.0.0.0( |$)'
]

OUTPUT = 'debug.txt'
OUTPUT_AGH = 'lists/compilation.txt'

# function that loads the filter list
def load_filters() -> str:
    text = ''
    for path in LOCAL_SOURCES:
        with open(path, 'r') as f:
            text += ''.join(f.readlines()) + '\n'
    for url in SOURCES:
        r = requests.get(url)
        text += r.text
    return text


def is_supported_agh(line) -> bool:
    for token in UNSUPPORTED_AGH:
        if token in line:
            return False

    return True

# function that prepares the filter list for AdGuard Home

def prepare_agh(lines) -> str:
    text = '\r\n'

    # remove or modifiy entries with unsupported modifiers
    for line in lines:

        if len(line) == 0:
            continue
        
        if line[0] not in ['!', '#']:
            line = re.sub(
                r"\d+?.\d+?.\d+?.\d+?\s+",
                "",
                line
            )

            line = re.sub(
                r"::1? ",
                "",
                line
            )

            for rule in FORBIDDEN_LINES:
                line = re.sub(
                    rule,
                    "",
                    line
                )

            line = re.sub(
                r"([$,])third-party",
                "",
                line
            )

            line = re.sub(
                r"([$,])~third-party",
                "",
                line
            )

            line = re.sub(
                r"([$,])3p",
                "",
                line
            )

            line = re.sub(
                r"([$,])first-party",
                "",
                line
            )

            line = re.sub(
                r"([$,])1p",
                "",
                line
            )

            line = re.sub(
                r"([$,])image",
                "",
                line
            )

            line = re.sub(
                r"([$,])media",
                "",
                line
            )

            line = re.sub(
                r"([$,])script",
                "",
                line
            )

            line = re.sub(
                r"([$,])popup",
                "",
                line
            )

            line = re.sub(
                r"([$,])popunder",
                "",
                line
            )

            line = re.sub(
                r"([$,])document",
                "",
                line
            )

            line = re.sub(
                r"([$,])subdocument",
                "",
                line
            )

            line = re.sub(
                r"([$,])~subdocument",
                "",
                line
            )

            line = re.sub(
                r"([$,])object",
                "",
                line
            )

            line = re.sub(
                r"([$,])~object-subrequest",
                "",
                line
            )

            line = re.sub(
                r"([$,])frame",
                "",
                line
            )

            line = re.sub(
                r"([$,])all",
                "",
                line
            )

            line = re.sub(
                r",important",
                "$important",
                line
            )

            line = re.sub(
                r"/\*$",
                "^",
                line
            )

            line = re.sub(
                r"(^|\|\|)\*\.",
                "",
                line
            )

            if len(line) > 0:
                if line[0] in ['/', '['] or line.startswith('@@/'):
                    continue
                if line[0] not in ['|', '@']:
                    if '.' not in line:
                        # Not a domain, ignore this
                        continue
                    line = '||' + line + '^'
            else:
                continue

        if is_supported_agh(line):
            text += line + '\r\n'
    unique = OrderedDict.fromkeys(text.splitlines(False))
    def removeComments(line):
        return len(line) > 0 and line[0] not in ['#', '!']
    rulesOnly = list(filter(removeComments, unique.items()))
    return '\r\n'.join(unique), len(rulesOnly)


if __name__ == "__main__":
    print('Starting the script')
    text = load_filters()
    lines = text.splitlines(False)
    print('Total number of lines: ' + str(len(lines)))

    agh_filter, count = prepare_agh(lines)


    with open(OUTPUT, "w") as text_file:
        text_file.write(text)

    with open(OUTPUT_AGH, "w") as text_file:
        text_file.write(f"""! Title: noads.online AdGuard Home Megalist
! Blocked: {count} domains
! Expires: 1 day
! Source: https://github.com/deletescape/noads
! Updated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}
! Licence: Dandelicence,
! https://github.com/DandelionSprout/Dandelicence/blob/master/DandelicenceV1.md
! This list is automatically generated by a script, DO NOT MODIFY
!
{agh_filter}""")

    print('Total number of rules: ' + str(count))
    print('The AGH rule version has been generated.')
