#!/usr/bin/python3

import io
import email
import gzip
import zipfile
from datetime import datetime
from email.utils import parsedate_tz, mktime_tz
from xml.dom import minidom
from requests.auth import HTTPBasicAuth
import boto3
import requests
import dns.resolver, dns.reversename

#Handling lambda
def lambda_handler(event, context):
    try:
        sourceKey = event['Records'][0]['s3']['object']['key']
        obj_to_file(sourceKey)
        file = open("/tmp/file", "r")
        mail = email.message_from_file(file)
        receiveDMARC(mail)
        file.close()
    except Exception as err:
        print(err)

#Validating file format
def receiveDMARC(mail):
    for part in mail.walk():
        type = part.get_content_type()
        if type == "application/gzip" or \
           type == "application/x-gzip" or \
           type == "application/gzip-compressed" or \
           type == "application/gzipped" or \
           type == "application/x-gunzip" or \
           type == "application/x-gzip-compressed" or \
           type == "gzip/document":
            print("     => Attachment: application/gzip")
            processDmarcXML(gzip.decompress(part.get_payload(decode=True)))
        elif type == "application/zip" or \
             type == "application/x-zip-compressed":
            attachedfile = io.BytesIO(part.get_payload(decode=True))
            with zipfile.ZipFile(attachedfile) as attachedzip:
                for zippedfiles in attachedzip.namelist():
                    print("     => Attachment: " + zippedfiles)
                    with attachedzip.open(zippedfiles) as zippedfile:
                        processDmarcXML(zippedfile.read())
        elif type == "text/xml":
            print("     => Attachment: text/xml")
            processDmarcXML(part.get_payload())

#DMARC fields processing
def processDmarcXML(xmlstring):
    xmldoc = minidom.parseString(xmlstring)
    report_metadata = xmldoc.getElementsByTagName("report_metadata")[0]
    date_range = report_metadata.getElementsByTagName("date_range")[0]
    policy_published = xmldoc.getElementsByTagName("policy_published")[0]
    enddate = date_range.getElementsByTagName("end")[0].firstChild.nodeValue
    reportid = report_metadata.getElementsByTagName("report_id")[0].firstChild.nodeValue
    metadata = {
        "report_metadata.org_name": report_metadata.getElementsByTagName("org_name")[0].firstChild.nodeValue,
        "report_metadata.email": report_metadata.getElementsByTagName("email")[0].firstChild.nodeValue,
        "report_metadata.report_id": reportid,
        "report_metadata.date.begin": str(datetime.fromtimestamp(int(date_range.getElementsByTagName("begin")[0].firstChild.nodeValue))),
        "report_metadata.date.end": str(datetime.fromtimestamp(int(enddate))),
        "policy_published.domain": policy_published.getElementsByTagName("domain")[0].firstChild.nodeValue,
        "policy_published.adkim": policy_published.getElementsByTagName("adkim")[0].firstChild.nodeValue,
        "policy_published.aspf": policy_published.getElementsByTagName("aspf")[0].firstChild.nodeValue,
        "policy_published.p": policy_published.getElementsByTagName("p")[0].firstChild.nodeValue,
        "policy_published.pct": policy_published.getElementsByTagName("pct")[0].firstChild.nodeValue,
    }
    if ("extra_contact_info") in metadata:
        metadata.update({
            "report_metadata.extra_contact_info": report_metadata.getElementsByTagName("extra_contact_info")[0].firstChild.nodeValue,
        })
    if ("sp") in metadata:
        metadata.update({
            "policy_published.sp": policy_published.getElementsByTagName("sp")[0].firstChild.nodeValue,
        })
    
    enddate_obj = datetime.fromtimestamp(int(enddate))
    indexdate = enddate_obj.strftime("%Y.%m.%d")
    metadata.update({
        "@timestamp": enddate_obj.isoformat(),
    })
    
    records = xmldoc.getElementsByTagName("record")
    for record in records:
        row = record.getElementsByTagName("row")[0]
        source_ip = row.getElementsByTagName("source_ip")[0].firstChild.nodeValue
        jsonrecord = {
            "row.source_ip": source_ip,
            "row.count": int(row.getElementsByTagName("count")[0].firstChild.nodeValue),
            "row.policy_evaluated.disposition": row.getElementsByTagName("disposition")[0].firstChild.nodeValue,
            "row.policy_evaluated.dkim": row.getElementsByTagName("dkim")[0].firstChild.nodeValue,
            "row.policy_evaluated.spf": row.getElementsByTagName("spf")[0].firstChild.nodeValue,
        }
        identifiers = record.getElementsByTagName("identifiers")[0]
        jsonrecord.update({
            "row.identifiers.header_from": identifiers.getElementsByTagName("header_from")[0].firstChild.nodeValue,
        })
        auth_results = record.getElementsByTagName("auth_results")[0]
        auth_results_dkim = auth_results.getElementsByTagName("dkim")
        if len(auth_results_dkim) > 0:        
            jsonrecord.update({
                "row.auth_results.dkim.domain": auth_results_dkim[0].getElementsByTagName("domain")[0].firstChild.nodeValue,
                "row.auth_results.dkim.result": auth_results_dkim[0].getElementsByTagName("result")[0].firstChild.nodeValue,
                "row.auth_results.dkim.selector": auth_results_dkim[0].getElementsByTagName("selector")[0].firstChild.nodeValue,
            })
        auth_results_spf = auth_results.getElementsByTagName("spf")
        if len(auth_results_spf) > 0:       
            jsonrecord.update({
                "row.auth_results.spf.domain": auth_results_spf[0].getElementsByTagName("domain")[0].firstChild.nodeValue,
                "row.auth_results.spf.result": auth_results_spf[0].getElementsByTagName("result")[0].firstChild.nodeValue,
                
            })
        source_ip_info = getDomain(source_ip)
        jsonrecord.update({
            "@timestamp": enddate_obj.isoformat(),
            "report_metadata.report_id": reportid,
            "source_ip_information.domain": source_ip_info,
        })
        jsonrecord.update(metadata)
        r = requests.post(elasticsearch + "dmarc-" + indexdate + "/_doc", json=jsonrecord, auth = HTTPBasicAuth(username, password), verify=False)
        r.close()       

#Getting Email ID and date
def getEmailIDandDate(mail):
    fields = mail["received"].split(";")
    date = datetime.fromtimestamp(mktime_tz(parsedate_tz(fields[len(fields)-1].strip())))
    id = ""
    words = fields[len(fields)-2].split()
    for index, word in enumerate(words):
        if word == "id":
            id = words[index+1]
    return id, date

#Resolving DNS 
def getDomain(ip):
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["8.8.8.8"]
        addrs = dns.reversename.from_address(ip)
        response = str(dns.resolver.resolve(addrs,"PTR")[0])
        return response
    except Exception as err:
        print(err)
        return "unknown"

#Writing s3 object content to file
def obj_to_file(key):
    client = boto3.client('s3')
    response = client.get_object(Bucket=bucket, Key=key)
    content = response['Body'].read().decode('utf-8')
    file = open("/tmp/file", "w+")
    file.write(content)
    file.close()
    return file

#Getting SSM credentials
def aws_getParameter(name):
    client = boto3.client('ssm')
    response = client.get_parameter(
        Name=name,
        WithDecryption=True
    )
    return response['Parameter']['Value']

bucket = "myBucket"
elasticsearch = "myElasticsearch"
username = aws_getParameter("username")
password = aws_getParameter("passwd")

if __name__ == "__main__":
    lambda_handler()