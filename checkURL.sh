#!/bin/bash

# Virus Total URL checker to search for malicious or suspicious URL's.
# example: ./check.sh http://ronnietucker.co.uk
# test urls below:
# http://ronnietucker.co.uk
# http://www.xhuru.artneoynk.com/

# Check if the URL was provided as a command line argument
if [[ $1 == "" ]]
then
  read -p "What is the url you would like to check? " site
else
  site=$1
fi
# Post the URL to Virus total to obtain results link
# input your VirusTotal x-apikey or into $VTKEY env variable
vtSite=$(curl -s --request POST \
  --url https://www.virustotal.com/api/v3/urls \
  --form url=$site \
  --header "x-apikey: $VTKEY" \
  | jq -r '.data.links.self')
# Get the results from the link provided above
# input your VirusTotal x-apikey or into $VTKEY env variable
results=$(curl -s --request GET \
  --url $vtSite \
  --header "x-apikey: $VTKEY" \
  | grep -i 'suspicious\|malicious')
# Extract number of Vendors flagging the URL
mal=$(echo $results | awk -F '[:,]' '{print $2}')
sus=$(echo $results | awk -F '[:,]' '{print $4}')
# Decide whether it was flagged as malicious or not
if [ $mal -eq 0 ]
then
  echo "It's not malicious: $mal"
elif [ $mal -gt 0 ]
then
  echo "It's mailicious: $mal"
else
  echo "Error occured!"
fi
# Decide whether it was flagged as malicious or not
if [ $sus -eq 0 ]
then
  echo "It's not suspicious: $sus"
elif [ $sus -gt 0 ]
then
  echo "It's suspicious: $sus"
else
  echo "Error occured!"
fi