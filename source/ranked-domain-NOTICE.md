# Majestic ranked-domain data

The rank/hostname projection in ranked-domain-candidates.csv is derived from
the first 250,000 rows of the Majestic Million, published by Majestic:
https://majestic.com/reports/majestic-million

Original download: https://downloads.majestic.com/majestic_million.csv
Licence: Creative Commons Attribution 3.0 Unported (CC BY 3.0):
https://creativecommons.org/licenses/by/3.0/

Only GlobalRank and Domain were retained; hostnames were lowercased and a
trailing DNS root dot removed. The ranking measures referring subnets, not
visits, local application usage, geographic ownership or blocking efficacy.
The data projection retains its upstream licence; repository code retains GPL-3.0.
