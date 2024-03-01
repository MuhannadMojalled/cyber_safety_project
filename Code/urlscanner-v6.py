import customtkinter as tk
from PIL import Image
from tkdial import Meter
from tkinter import filedialog
import tkinter as tkk
from tkinter import messagebox
import requests
import json
import time
import shutil
import math
import cv2
import openai
import threading
from pyzbar.pyzbar import decode
import string
import pyzbar
import PyPDF2
from PyPDF2 import PdfReader
from langchain.text_splitter import CharacterTextSplitter
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS
from langchain.chat_models import ChatOpenAI
from langchain.memory import ConversationBufferMemory
from langchain.chains import ConversationalRetrievalChain
from langchain.chains.question_answering import load_qa_chain
from langchain.llms import OpenAI
from pathlib import Path
import os
import sys


tk.set_appearance_mode("dark")
tk.set_default_color_theme("dark-blue")

# open ai api key
global api_key
api_key = "Open AI API Key"
openai.api_key = api_key
# Urlscan.io api key
global urlSAPI
urlSAPI = "UrlScanner.io Api key"
# virustotal api key
global vTAPI
vTAPI = "Virustotal Api key"


def resource_path(relative_path):
    # a method to help with finding the path to the exe program
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


def restore_window():
    # a method to clear the screen for tab 1
    textboxa.configure(state="normal")
    textboxa2.configure(state="normal")
    textboxa3.configure(state="normal")
    textboxa3.delete("1.0", "end")
    textboxa.delete("1.0", "end")
    textboxa2.delete("1.0", "end")
    textboxa.configure(state="disabled")
    textboxa3.configure(state="disabled")
    textboxa2.configure(state="disabled")
    textboxa.pack_forget()
    textboxa2.pack_forget()
    textboxa3.pack_forget()
    entrya.delete(0, "end")
    text_labela.pack_forget()
    text_label5a.pack_forget()
    text_label6a.pack_forget()
    text_label7a.pack_forget()
    text_label8a.pack_forget()
    text_label9a.pack_forget()
    text_label10a.pack_forget()
    text_label11a.pack_forget()
    text_label12a.pack_forget()
    text_label13a.pack_forget()
    text_label14a.pack_forget()
    text_label15a.pack_forget()
    text_label17a.pack_forget()
    text_label18a.pack_forget()
    text_label19a.pack_forget()
    metera.pack_forget()
    progbara.pack_forget()
    progbara2.pack_forget()
    progbara3.pack_forget()
    button3a.pack_forget()
    button4a.pack_forget()
    buttona.pack(pady=5, padx=10, side="left")
    window.update()


def display_content():
    # the main method to scan a url

    global done
    done = True

    # making the labels blank and load meter
    text_labela.configure(text="", text_color="white")
    text_label5a.configure(text="")
    text_label6a.configure(text="")
    text_label7a.configure(text="")
    text_label8a.configure(text="")
    text_label9a.configure(text="")
    text_label10a.configure(text="")
    text_label11a.configure(text="")
    text_label12a.configure(text="")
    text_label13a.configure(text="")
    text_label14a.configure(text="")
    metera.configure()

    # asks the user for the link
    link = entrya.get()

    # post the request to urlscan.io
    global urlSAPI
    headers = {
        "API-Key": urlSAPI,
        "Content-Type": "application/json",
    }
    data = {"url": link, "visibility": "public"}

    text_labela.pack(pady=5)

    # try to reach urlscan.io
    try:
        response = requests.post(
            "https://urlscan.io/api/v1/scan/", headers=headers, data=json.dumps(data)
        )
    except:
        text_labela.configure(text="UrlScan.io Scan is Unsuccessfull")
        messagebox.showerror(
            "UrlScan.io Eror",
            "Error: Unable to reach UrlScan.io, check your internet connection",
        )
        exit()

    # post the request to virustotal
    urlV1 = "https://www.virustotal.com/vtapi/v2/url/scan"
    global vTAPI
    paramsV1 = {
        "apikey": vTAPI,
        "url": link,
    }

    # try to reach virustotal
    try:
        responseV1 = requests.post(urlV1, data=paramsV1)
    except:
        text_labela.configure(text="Virustotal Scan is Unsuccessfull")
        messagebox.showerror(
            "VirusTotal Eror",
            "Error: Unable to reach VirusTotal, check your internet connection",
        )
        return

    timeO = 0
    # while the virus total response code is not 200, wait and then request again
    while responseV1.status_code != 200:
        time.sleep(4)
        timeO += 4
        text_labela.configure(text="Loading... just a few seconds...")
        window.update()
        responseV1 = requests.post(urlV1, data=paramsV1)
        if timeO >= 14:
            text_labela.configure(text="Virustotal Scan is Unsuccessfull")
            done = True
            return
    # try to get the scan id from virustotal
    try:
        scanID = responseV1.json().get("scan_id")
    except:
        text_labela.configure(text="Virustotal Scan is Unsuccessfull")

    # if the urlscan.io response code is not 200
    if response.status_code != 200:
        text_labela.configure(
            text="This link is blacklisted or invalid", text_color="red"
        )
        time.sleep(1)
        window.update()
        done = True
        return

    # if the urlscan.io response code is 200
    else:
        # get the uuid from the response
        x = response.json().get("uuid")
        text_labela.configure(text="Loading...")
        window.update()

        # load the progbar
        progbara.anchor("n")
        progbara.pack(pady=5)
        progbara.set(0)

        # preforming the loading
        for i in range(499):
            time.sleep(0.015)
            progbara.start()
            progbara.stop()
            window.update()

        # getting the response from urlscan.io
        response2 = requests.get("https://urlscan.io/api/v1/result/" + x + "/")

        timeO = 0

        # if the response is not 200, wait
        while response2.status_code != 200:
            time.sleep(2)
            timeO += 2
            text_labela.configure(text="Loading... just a few seconds...")
            window.update()
            response2 = requests.get("https://urlscan.io/api/v1/result/" + x + "/")
            if timeO >= 10:
                text_labela.configure(text="Scan is Unsuccessfull")
                return

        # if the scan is successfull
        text_labela.configure(text="Scan is successfull")

        # get the response from virustotal
        urlV2 = "https://www.virustotal.com/vtapi/v2/url/report"
        paramsV2 = {
            "apikey": vTAPI,
            "resource": scanID,
        }

        # get the results from virus total
        responseV2 = requests.get(urlV2, params=paramsV2)

        timeO = 0

        # while the status code is not 200, wait and try again
        while responseV2.status_code != 200:
            time.sleep(2)
            timeO += 2
            text_labela.configure(text="Loading... just a few seconds...")
            window.update()
            responseV2 = requests.get(urlV2, params=paramsV2)
            if timeO >= 14:
                text_labela.configure(text="Scan is Unsuccessfull")
                exit

        # getting the urlscan.io results
        verdict_info = response2.json().get("verdicts")
        is_malicious = verdict_info.get("overall").get("malicious")
        score = verdict_info.get("overall").get("score")
        malicious_total = verdict_info.get("engines").get("maliciousTotal")
        category = verdict_info.get("overall").get("categories")

        # to get the redirected links
        allData = response2.json().get("data")
        Redirectedlinks = []
        d = 0
        for requests2 in allData.items():
            t = allData.get("requests")[d].get("request")
            redirect = "redirectHasExtraInfo"
            if redirect in t:
                a = t.get("redirectHasExtraInfo")
                if a:
                    l = t.get("redirectResponse").get("url")
                    if l in Redirectedlinks:
                        break
                    else:
                        Redirectedlinks.append(l)

        text_label15a.pack()

        # getting the results from virustotal
        positives = responseV2.json().get("positives")
        total_scans = responseV2.json().get("total")
        response3 = requests.get(
            "https://urlscan.io/screenshots/" + x + ".png", stream=True
        )

        # saving the image
        with open("img.png", "wb") as out_file:
            shutil.copyfileobj(response3.raw, out_file)
        del response3

        # to get the result from urlscan.io to add into the total and display
        urlS = 0
        if score <= 0:
            # some websites shows score below 0 while being safe
            score = 0
            s = "Safe"
            text_label5a.configure(text_color="green")
        else:
            urlS = 5
            s = "Not safe"
            text_label5a.configure(text_color="red")

        text_label5a.pack()

        # displaying the text
        textM = (
            "Malicious: "
            + str(is_malicious)
            + ",   Malicious Requests: "
            + str(malicious_total)
        )
        text_label5a.configure(text="URLSCAN.IO results: " + s)

        # to display the categories of the unsafe links
        if score > 0:
            text_label8a.pack()
            text_label10a.pack()
            text_label8a.configure(text=textM)
            text_label10a.configure(
                text="Categories: "
                + str(category).replace("'", "").replace("[", "").replace("]", "")
            )

        # to get the score out of 90 for virustotal
        percentageV = (positives / total_scans) * 100
        avg = math.floor((percentageV + score) / 2)

        # display the virus total results
        dataV2 = responseV2.json().get("scans")
        no = total_scans
        textboxa.tag_config("clean", foreground="green")
        textboxa.tag_config("not", foreground="red")
        textboxa.tag_config("susp", foreground="yellow")
        textboxa.pack()
        danger = 0
        dangert = ""

        # to count the nummber of each category for each of the virustotal 90 websites
        clean = 0
        spam = 0
        susp = 0
        mal = 0
        phi = 0
        malw = 0

        # go through the virustotal results and count each category
        for name, values in dataV2.items():
            window.update()
            tagR = ""
            if "malware site" in values["result"]:
                malw += 1
                tagR = "not"
                if danger < 6:
                    danger = 6
                    dangert = "malware site"
            if "phishing site" in values["result"]:
                phi += 1
                tagR = "not"
                if danger < 5:
                    danger = 5
                    dangert = "phishing site"
            if "malicious site" in values["result"]:
                mal += 1
                tagR = "not"
                if danger < 4:
                    danger = 4
                    dangert = "malicious site"
            if "spam site" in values["result"]:
                spam += 1
                tagR = "susp"
                if danger < 3:
                    danger = 3
                    dangert = "spam site"
            if "suspicious site" in values["result"]:
                susp += 1
                tagR = "susp"
                if danger < 2:
                    danger = 2
                    dangert = "suspicious site"
            if "unrated site" in values["result"]:
                clean += 1
            if "clean site" in values["result"]:
                clean += 1
                tagR = "clean"
                if danger == 0:
                    dangert = "Clean site"

            # inserting the data into the text box to display the virustotal results
            data = str(no) + "- " + name + " : " + values["result"] + "    \n"
            textboxa.configure(state="normal")
            textboxa.insert("0.0", data, tags=tagR)
            textboxa.configure(state="disabled")

            no = no - 1
            if no == 0:
                textboxa.configure(state="normal")
                textboxa.insert("0.0", "VIRUSTOTAL results: \n")
                textboxa.configure(state="disabled")

        # calculate the value for each one  of the types
        Sclean = 0 * clean
        Sspam = 1 * spam
        Ssusp = 2 * susp
        Smal = 3 * mal
        Sphi = 4 * phi
        Smalw = 5 * malw

        # the highest score
        amount = 5 * (clean + spam + susp + mal + phi + malw + 1)

        # the overall score
        ovscore = Sclean + Sspam + Ssusp + Smal + Sphi + Smalw + urlS
        vs = 0

        if ovscore <= 2:
            # if the result is less than two
            vs = ovscore * 10
            metera.set(vs)
            text = "Score " + str(ovscore) + "/" + str(amount)
            metera.configure(text=text, text_color="green", border_color="green")
            text_label13a.configure(text_color="green")
            savg = "Safe"
        elif ovscore > 2 and ovscore <= 4:
            # if the result is between three and four
            vs = ovscore * 10
            metera.set(vs)
            text = "Score " + str(ovscore) + "/" + str(amount)
            metera.configure(text=text, text_color="yellow", border_color="yellow")
            savg = "Suspicious"
            text_label13a.configure(text_color="yellow")
        else:
            # if the score is larger than 4
            if ovscore <= 40:
                vs = ovscore + 40
            elif 40 < ovscore < 100:
                vs = ovscore + 10
            else:
                vs = ovscore
            metera.set(ovscore)
            text = "Score " + str(ovscore) + "/" + str(amount)
            metera.configure(text=text, text_color="red", border_color="red")
            savg = "Not safe"
            text_label13a.configure(text_color="red")

        if danger == 0:
            # if the result is zero
            text_label11a.configure(text_color="green")
        elif danger == 2 or danger == 3:
            # if the result is between 2 and 3
            text_label11a.configure(text_color="yellow")
        elif danger == 4 or danger == 5:
            # if the result is between 5 and 4
            text_label11a.configure(text_color="red")
        elif danger == 6:
            # if the result is 6
            text_label11a.configure(text_color="red")

        # printing the virustotal result
        text_label11a.pack()
        text_label11a.configure(
            text="VIRUSTOTAL results: "
            + str(positives)
            + "/"
            + str(total_scans)
            + "\n the site is reported as a "
            + dangert
        )

        window.update()

        # displaying the overall result
        text_label13a.pack()
        text_label13a.configure(text="Overall results: " + savg)

        metera.pack(pady=5)
        window.update()

        # opening the screenshot in the screenshot tab
        im = Image.open(resource_path(os.path.dirname(sys.argv[0]) + ".\img.png"))
        button4a.configure(command=lambda: [im.show()])
        button4a.pack(pady=5, side="bottom")
        screenshot = tk.CTkImage(im, size=(500, 375))
        screenshot_label = tk.CTkLabel(
            frame2.tab("Screenshot"), text="", image=screenshot
        )
        screenshot_label.pack(pady=5)

        text_label9a.pack()
        text_label9a.configure(text="Screenshot successfully loaded!")
        window.update()

        # scaning the redirects
        text_label17a.pack()
        text_label17a.configure(text="Scanning all Redirects...")
        window.update()
        redirects_handling(Redirectedlinks)
        Redirectedlinks.clear()

        # getting all the links in the page
        linksinpage = response2.json().get("lists").get("linkDomains")
        lnum = 1
        textboxa3.pack()
        for linkinpage in linksinpage:
            nums = str(lnum) + "- "
            textboxa3.configure(state="normal")
            textboxa3.insert(tk.END, nums + linkinpage + " \n")
            textboxa3.configure(state="disabled")
            global linkstoscan
            linkstoscan.append(linkinpage)
            lnum += 1

    # a button if the user wants to clear the screen and search another link
    button2a.configure(
        command=lambda: [
            restore_window(),
            button2a.pack_forget(),
            screenshot_label.pack_forget(),
        ]
    )
    button2a.pack(pady=5, side="bottom")

    # if the user wants to scan all links in page
    button3a.pack(pady=5, side="bottom")


def redirects_handling(links):
    # a method to handel the redirects scaning
    n = len(links)
    if n == 0:
        text_label17a.configure(text="No Redirects is found")
        text_label15a.configure(text="No Redirects is found")
        return

    for ls in links:
        if done:
            threading.Thread(target=scan_redirects(ls, n)).join
        else:
            threading.Thread(target=scan_redirects(ls, n)).start
        n = n - 1

    text_label17a.configure(text="Scanning all Redirects is successful")
    text_label15a.configure(text="Scanning all Redirects is successful")
    links.clear()


def scan_redirects(ls, n):
    # a method to scan the redirects

    # post the request to urlscan.io
    global urlSAPI
    headers = {
        "API-Key": urlSAPI,
        "Content-Type": "application/json",
    }
    data = {"url": ls, "visibility": "public"}
    response = requests.post(
        "https://urlscan.io/api/v1/scan/", headers=headers, data=json.dumps(data)
    )

    # post the request to virustotal
    global vTAPI
    urlV = "https://www.virustotal.com/vtapi/v2/url/scan"
    paramsV = {
        "apikey": vTAPI,
        "url": ls,
    }

    responseV = requests.post(urlV, data=paramsV)

    timeO = 0
    while responseV.status_code != 200:
        time.sleep(2)
        timeO += 2
        text_label15a.configure(text="Loading... just a few seconds...")
        text_label15a.pack(pady=5)
        window.update()
        responseV = requests.post(urlV, data=paramsV)
        if timeO >= 14:
            text_label15a.configure(text="Virustotal Scan is Unsuccessfull")
            text_label17a.configure(text="Virustotal Scan is Unsuccessfull")
            text_label15a.pack(pady=5)
            done = True
            return

    # if the urlscan.io response code is not 200
    if response.status_code != 200:
        text_label15a.configure(
            text="This link is blacklisted or invalid", text_color="red"
        )
        time.sleep(1)
        window.update()
        done = True
        return

    # if the urlscan.io response code is 200
    else:
        scanID = responseV.json().get("scan_id")

        # get the uuid from the response
        x = response.json().get("uuid")
        text_label15a.configure(text="Scanning all redirects...")
        text_label15a.pack(pady=5)
        window.update()

        # load the progbar
        progbara2.anchor("n")
        progbara2.pack(pady=5)
        progbara2.set(0)
        textboxa2.pack()

        # preforming the loading
        for i in range(499):
            time.sleep(0.015)
            progbara2.start()
            progbara2.stop()
            window.update()

        # getting the response from urlscan.io
        response2 = requests.get("https://urlscan.io/api/v1/result/" + x + "/")

        timeO = 0

        # if the response is not 200, wait
        while response2.status_code != 200:
            time.sleep(2)
            timeO += 2
            text_label15a.configure(text="Scanning all redirects... please wait...")
            window.update()
            response2 = requests.get("https://urlscan.io/api/v1/result/" + x + "/")
            if timeO >= 14:
                text_label15a.configure(text="Scan is Unsuccessfull")
                exit

        # if the scan is successfull
        text_label15a.configure(text="Scan is successfull")

        # get the response from virustotal
        urlV2 = "https://www.virustotal.com/vtapi/v2/url/report"
        paramsV2 = {
            "apikey": vTAPI,
            "resource": scanID,
        }
        responseV2 = requests.get(urlV2, params=paramsV2)
        timeO = 0
        while responseV2.status_code != 200:
            time.sleep(2)
            timeO += 2
            text_label15a.configure(text="Loading... just a few seconds...")
            window.update()
            responseV2 = requests.get(urlV2, params=paramsV2)
            if timeO >= 14:
                text_label15a.configure(text="Scan is Unsuccessfull")
                exit

        verdict_info = response2.json().get("verdicts")
        is_malicious = verdict_info.get("overall").get("malicious")
        score = verdict_info.get("overall").get("score")
        malicious_total = verdict_info.get("engines").get("maliciousTotal")
        category = verdict_info.get("overall").get("categories")

        positives = responseV2.json().get("positives")
        total_scans = responseV2.json().get("total")

        textboxa.tag_config("safe", foreground="green")
        textboxa.tag_config("not", foreground="red")
        if score <= 0:
            # some websites shows score below 0 while being safe
            score = 0
            s = "Safe"
            tag = "safe"
        else:
            s = "Not safe"
            tag = "not"

        dataURL = (
            "URLSCAN.IO results: "
            + s
            + ", The URL is : "
            + str(score)
            + "% malicious  \n"
        )

        textboxa2.tag_config("safe", foreground="green")
        textboxa2.tag_config("msafe", foreground="#90EE90")
        textboxa2.tag_config("susp", foreground="yellow")
        textboxa2.tag_config("not", foreground="red")

        percentageV = (positives / total_scans) * 100
        if percentageV <= 0:
            # if the result is zero
            sv = "Safe"
            tagv = "safe"
        elif percentageV >= 1 and percentageV <= 10:
            # if the result is between 1 and 10
            sv = "Mostly safe"
            tagv = "msafe"
        elif percentageV >= 11 and percentageV <= 35:
            # if the result is between 11 and 35
            sv = "Suspicious"
            tagv = "susp"
        else:
            # if the result is more than 35
            sv = "Not safe"
            tagv = "not"

        dataV = (
            "VIRUSTOTAL results: "
            + sv
            + ", The URL is : "
            + str(math.floor(percentageV))
            + "% malicious  \n"
        )

        urlinfo = str(n) + ". " + str(ls) + " \n"
        textboxa2.configure(state="normal")
        textboxa2.insert(tk.END, urlinfo)
        textboxa2.insert(tk.END, dataURL, tags=tag)
        textboxa2.insert(tk.END, dataV, tags=tagv)
        textboxa2.configure(state="disabled")
        done = True


def threading_scan():
    # a method to thread the main scaning method
    if done:
        threading.Thread(target=display_content()).join
    else:
        threading.Thread(target=display_content()).start


def handling_scan_all_links():
    # mathod to handel scanning all links
    textboxa3.configure(state="normal")
    textboxa3.delete("1.0", tk.END)
    textboxa3.configure(state="disabled")
    textboxa3.pack_forget()
    global linkstoscan
    n = len(linkstoscan)
    n2 = 1
    if n == 0:
        text_label18a.configure(text="No other links were found")
        text_label19a.configure(text="No other links were found")
        return

    for ls in linkstoscan:
        if done:
            threading.Thread(target=scan_all_links(ls, n, n2)).join
        else:
            threading.Thread(target=scan_all_links(ls, n, n2)).start
        n = n - 1
        n2 += 1

    text_label18a.configure(text="Scanning all links is successful")
    text_label19a.configure(text="Scanning all links is successful")
    linkstoscan.clear()


def scan_all_links(ls, n, n2):
    # a method to scan all links
    # post the request to urlscan.io
    global urlSAPI
    headers = {
        "API-Key": urlSAPI,
        "Content-Type": "application/json",
    }
    data = {"url": ls, "visibility": "public"}
    response = requests.post(
        "https://urlscan.io/api/v1/scan/", headers=headers, data=json.dumps(data)
    )

    # post the request to virustotal
    global vTAPI
    urlV = "https://www.virustotal.com/vtapi/v2/url/scan"
    paramsV = {
        "apikey": vTAPI,
        "url": ls,
    }

    responseV = requests.post(urlV, data=paramsV)

    timeO = 0

    while responseV.status_code != 200:
        time.sleep(4)
        timeO += 4
        text_label19a.configure(
            text="Loading... just a few seconds..." + " links to scan:" + str(n)
        )
        text_label19a.pack(pady=5)
        window.update()
        responseV = requests.post(urlV, data=paramsV)
        if timeO >= 24:
            text_label19a.configure(text="Virustotal Scan is Unsuccessfull")
            text_label18a.configure(text="Virustotal Scan is Unsuccessfull")
            text_label19a.pack(pady=5)
            done = True
            exit

    timeU = 0
    # if the urlscan.io response code is not 200
    if response.status_code != 200:
        urlinfo = str(n2) + ". " + str(ls) + " \n"
        errormsg = "Error: This link is blacklisted or invalid \n"
        textboxa3.configure(state="normal")
        textboxa3.insert(tk.END, urlinfo)
        textboxa3.insert(tk.END, errormsg)
        textboxa3.configure(state="disabled")
        time.sleep(1)
        window.update()
        done = True
        return

    # if the urlscan.io response code is 200
    else:
        scanID = responseV.json().get("scan_id")

        # get the uuid from the response
        x = response.json().get("uuid")
        text_label19a.configure(
            text="Scanning all Links in page..." + " links to scan:" + str(n)
        )
        text_label19a.pack(pady=5)
        text_label18a.configure(
            text="Scanning all Links in page..." + " links to scan:" + str(n)
        )
        text_label18a.pack(pady=10)
        window.update()

        # load the progbar
        progbara3.anchor("n")
        progbara3.pack(pady=5)
        progbara3.set(0)
        textboxa3.pack()

        # preforming the loading
        for i in range(499):
            time.sleep(0.035)
            progbara3.start()
            progbara3.stop()
            window.update()

        # getting the response from urlscan.io
        response2 = requests.get("https://urlscan.io/api/v1/result/" + x + "/")

        timeO = 0

        # if the response is not 200, wait
        while response2.status_code != 200:
            time.sleep(2)
            timeO += 2
            text_label19a.configure(
                text="Scanning all links in page... please wait..."
                + " links to scan:"
                + str(n)
            )
            window.update()
            response2 = requests.get("https://urlscan.io/api/v1/result/" + x + "/")
            if timeO >= 10:
                text_label19a.configure(text="Scan is Unsuccessfull")
                text_label18a.configure(text="Scan is Unsuccessfull")
                exit

        # get the response from virustotal
        urlV2 = "https://www.virustotal.com/vtapi/v2/url/report"
        paramsV2 = {
            "apikey": vTAPI,
            "resource": scanID,
        }
        responseV2 = requests.get(urlV2, params=paramsV2)
        timeO = 0
        while responseV2.status_code != 200:
            time.sleep(2)
            timeO += 2
            text_label19a.configure(
                text="Loading... just a few seconds..." + " links to scan:" + str(n)
            )
            window.update()
            responseV2 = requests.get(urlV2, params=paramsV2)
            if timeO >= 14:
                text_label19a.configure(text="Scan is Unsuccessfull")
                text_label18a.configure(text="Scan is Unsuccessfull")
                exit

        verdict_info = response2.json().get("verdicts")
        is_malicious = verdict_info.get("overall").get("malicious")
        score = verdict_info.get("overall").get("score")
        malicious_total = verdict_info.get("engines").get("maliciousTotal")
        category = verdict_info.get("overall").get("categories")

        positives = responseV2.json().get("positives")
        total_scans = responseV2.json().get("total")

        textboxa.tag_config("safe", foreground="green")
        textboxa.tag_config("not", foreground="red")
        if score <= 0:
            # some websites shows score below 0 while being safe
            score = 0
            s = "Safe"
            tag = "safe"
        else:
            s = "Not safe"
            tag = "not"

        dataURL = (
            "URLSCAN.IO results: "
            + s
            + ", The URL is : "
            + str(score)
            + "% malicious  \n"
        )

        textboxa3.tag_config("safe", foreground="green")
        textboxa3.tag_config("msafe", foreground="#90EE90")
        textboxa3.tag_config("susp", foreground="yellow")
        textboxa3.tag_config("not", foreground="red")

        percentageV = (positives / total_scans) * 100
        if percentageV <= 0:
            # if the result is zero
            sv = "Safe"
            tagv = "safe"
        elif percentageV >= 1 and percentageV <= 10:
            # if the result is between 1 and 10
            sv = "Mostly safe"
            tagv = "msafe"
        elif percentageV >= 11 and percentageV <= 35:
            # if the result is between 11 and 35
            sv = "Suspicious"
            tagv = "susp"
        else:
            # if the result is more than 35
            sv = "Not safe"
            tagv = "not"

        dataV = (
            "VIRUSTOTAL results: "
            + sv
            + ", The URL is : "
            + str(math.floor(percentageV))
            + "% malicious  \n"
        )

        urlinfo = str(n2) + ". " + str(ls) + " \n"
        textboxa3.configure(state="normal")
        textboxa3.insert(tk.END, urlinfo)
        textboxa3.insert(tk.END, dataURL, tags=tag)
        textboxa3.insert(tk.END, dataV, tags=tagv)
        textboxa3.configure(state="disabled")
        done = True


def restore_window_for_QR():
    # a method to clear the screen for the second tab
    textboxb.configure(state="normal")
    textboxb2.configure(state="normal")
    textboxb3.configure(state="normal")
    textboxb.delete("1.0", "end")
    textboxb2.delete("1.0", "end")
    textboxb3.delete("1.0", "end")
    textboxb.configure(state="disabled")
    textboxb2.configure(state="disabled")
    textboxb3.configure(state="disabled")
    textboxb.pack_forget()
    textboxb2.pack_forget()
    textboxb3.pack_forget()
    text_labelb.pack_forget()
    text_label5b.pack_forget()
    text_label6b.pack_forget()
    text_label7b.pack_forget()
    text_label8b.pack_forget()
    text_label9b.pack_forget()
    text_label10b.pack_forget()
    text_label11b.pack_forget()
    text_label12b.pack_forget()
    text_label13b.pack_forget()
    text_label14b.pack_forget()
    text_label15b.pack_forget()
    text_label17b.pack_forget()
    text_label18b.pack_forget()
    text_label19b.pack_forget()
    qr_code_result.pack_forget()
    button1b.pack_forget()
    meterb.pack_forget()
    progbarb.pack_forget()
    progbarb2.pack_forget()
    progbarb3.pack_forget()
    button3b.pack_forget()
    button4b.pack_forget()
    buttonb.pack(pady=5, padx=50)
    window.update()


def display_content_for_QR():
    global done
    done = True

    # making the labels blank and load meter
    text_labelb.configure(text="", text_color="white")
    text_label5b.configure(text="")
    text_label6b.configure(text="")
    text_label7b.configure(text="")
    text_label8b.configure(text="")
    text_label9b.configure(text="")
    text_label10b.configure(text="")
    text_label11b.configure(text="")
    text_label12b.configure(text="")
    text_label13b.configure(text="")
    text_label14b.configure(text="")
    meterb.configure()

    # asks the user for the link
    link = qr_code_data

    # post the request to urlscan.io
    global urlSAPI
    headers = {
        "API-Key": urlSAPI,
        "Content-Type": "application/json",
    }
    data = {"url": link, "visibility": "public"}
    try:
        response = requests.post(
            "https://urlscan.io/api/v1/scan/", headers=headers, data=json.dumps(data)
        )
    except:
        text_labelb.configure(text="UrlScan.io Scan is Unsuccessfull")
        text_labelb.pack(pady=5)
        messagebox.showerror(
            "UrlScan.io Eror",
            "Error: Unable to reach UrlScan.io, check your internet connection",
        )
        exit()

    text_labelb.pack(pady=5)

    # post the request to virustotal
    global vTAPI
    urlV1 = "https://www.virustotal.com/vtapi/v2/url/scan"
    paramsV1 = {
        "apikey": vTAPI,
        "url": link,
    }

    try:
        responseV1 = requests.post(urlV1, data=paramsV1)
    except:
        text_labelb.configure(text="Virustotal Scan is Unsuccessfull")
        messagebox.showerror(
            "VirusTotal Eror",
            "Error: Unable to reach VirusTotal, check your internet connection",
        )
        exit()

    timeO = 0
    while responseV1.status_code != 200:
        time.sleep(2)
        timeO += 2
        text_labelb.configure(text="Loading... just a few seconds...")
        window.update()
        responseV1 = requests.post(urlV1, data=paramsV1)
        if timeO >= 14:
            text_labelb.configure(text="Virustotal Scan is Unsuccessfull")
            done = True
            exit
    try:
        scanID = responseV1.json().get("scan_id")
    except:
        text_labelb.configure(text="Virustotal Scan is Unsuccessfull")

    # if the urlscan.io response code is not 200
    if response.status_code != 200:
        text_labelb.configure(
            text="This link is blacklisted or invalid", text_color="red"
        )
        time.sleep(1)
        window.update()
        done = True
        exit

    # if the urlscan.io response code is 200
    else:
        # get the uuid from the response
        x = response.json().get("uuid")
        text_labelb.configure(text="Loading...")
        window.update()

        # load the progbar
        progbarb.anchor("n")
        progbarb.pack(pady=5)
        progbarb.set(0)

        # preforming the loading
        for i in range(499):
            time.sleep(0.015)
            progbarb.start()
            progbarb.stop()
            window.update()

        # getting the response from urlscan.io
        try:
            response2 = requests.get("https://urlscan.io/api/v1/result/" + x + "/")
        except:
            text_labelb.configure(text="")

        timeO = 0

        # if the response is not 200, wait
        while response2.status_code != 200:
            time.sleep(2)
            timeO += 2
            text_labelb.configure(text="Loading... just a few seconds...")
            window.update()
            response2 = requests.get("https://urlscan.io/api/v1/result/" + x + "/")
            if timeO >= 10:
                text_labelb.configure(text="Scan is Unsuccessfull")
                exit

        # if the scan is successfull
        text_labelb.configure(text="Scan is successfull")

        # get the response from virustotal
        urlV2 = "https://www.virustotal.com/vtapi/v2/url/report"
        paramsV2 = {
            "apikey": vTAPI,
            "resource": scanID,
        }

        responseV2 = requests.get(urlV2, params=paramsV2)

        timeO = 0
        while responseV2.status_code != 200:
            time.sleep(2)
            timeO += 2
            text_labelb.configure(text="Loading... just a few seconds...")
            window.update()
            responseV2 = requests.get(urlV2, params=paramsV2)
            if timeO >= 14:
                text_labelb.configure(text="Scan is Unsuccessfull")
                exit

        # getting the urlscan.io results
        verdict_info = response2.json().get("verdicts")
        is_malicious = verdict_info.get("overall").get("malicious")
        score = verdict_info.get("overall").get("score")
        malicious_total = verdict_info.get("engines").get("maliciousTotal")
        category = verdict_info.get("overall").get("categories")

        # to get the redirected links
        allData = response2.json().get("data")
        Redirectedlinks = []
        d = 0
        for requests2 in allData.items():
            t = allData.get("requests")[d].get("request")
            redirect = "redirectHasExtraInfo"
            if redirect in t:
                a = t.get("redirectHasExtraInfo")
                if a:
                    l = t.get("redirectResponse").get("url")
                    if l in Redirectedlinks:
                        break
                    else:
                        Redirectedlinks.append(l)

        text_label15b.pack()

        # getting the results from virustotal
        positives = responseV2.json().get("positives")
        total_scans = responseV2.json().get("total")
        response3 = requests.get(
            "https://urlscan.io/screenshots/" + x + ".png", stream=True
        )

        # saving the image
        with open("img.png", "wb") as out_file:
            shutil.copyfileobj(response3.raw, out_file)
        del response3

        urlS = 0
        if score <= 0:
            # some websites shows score below 0 while being safe
            score = 0
            s = "Safe"
            text_label5b.configure(text_color="green")
        else:
            urlS = 5
            s = "Not safe"
            text_label5b.configure(text_color="red")

        text_label5b.pack()
        # text_label6b.pack()

        # displaying the text
        textM = (
            "Malicious: "
            + str(is_malicious)
            + ",   Malicious Requests: "
            + str(malicious_total)
        )
        window.update()
        text_label5b.configure(text="URLSCAN.IO results: " + s)
        # text_label6b.configure(text="The URL is " + str(score) + "% malicious")

        window.update()
        if score > 0:
            text_label8b.pack()
            text_label10b.pack()
            text_label8b.configure(text=textM)
            text_label10b.configure(
                text="Categories: "
                + str(category).replace("'", "").replace("[", "").replace("]", "")
            )

        percentageV = (positives / total_scans) * 100

        avg = math.floor((percentageV + score) / 2)
        window.update()

        # display the virus total results
        dataV2 = responseV2.json().get("scans")
        no = total_scans
        textboxb.tag_config("clean", foreground="green")
        textboxb.tag_config("not", foreground="red")
        textboxb.tag_config("susp", foreground="yellow")
        textboxb.pack()
        danger = 0
        dangert = ""

        clean = 0
        spam = 0
        susp = 0
        mal = 0
        phi = 0
        malw = 0

        for name, values in dataV2.items():
            window.update()
            tagR = ""
            if "malware site" in values["result"]:
                malw += 1
                tagR = "not"
                if danger < 6:
                    danger = 6
                    dangert = "malware site"
            if "phishing site" in values["result"]:
                phi += 1
                tagR = "not"
                if danger < 5:
                    danger = 5
                    dangert = "phishing site"
            if "malicious site" in values["result"]:
                mal += 1
                tagR = "not"
                if danger < 4:
                    danger = 4
                    dangert = "malicious site"
            if "spam site" in values["result"]:
                spam += 1
                tagR = "susp"
                if danger < 3:
                    danger = 3
                    dangert = "spam site"
            if "suspicious site" in values["result"]:
                susp += 1
                tagR = "susp"
                if danger < 2:
                    danger = 2
                    dangert = "suspicious site"
            if "unrated site" in values["result"]:
                clean += 1
            if "clean site" in values["result"]:
                clean += 1
                tagR = "clean"
                if danger == 0:
                    dangert = "Clean site"

            data = str(no) + "- " + name + " : " + values["result"] + "    \n"
            textboxb.configure(state="normal")
            textboxb.insert("0.0", data, tags=tagR)
            textboxb.configure(state="disabled")

            no = no - 1
            if no == 0:
                textboxb.configure(state="normal")
                textboxb.insert("0.0", "VIRUSTOTAL results: \n")
                textboxb.configure(state="disabled")

        Sclean = 0 * clean
        Sspam = 1 * spam
        Ssusp = 2 * susp
        Smal = 3 * mal
        Sphi = 4 * phi
        Smalw = 5 * malw

        amount = 5 * (clean + spam + susp + mal + phi + malw + 1)

        ovscore = Sclean + Sspam + Ssusp + Smal + Sphi + Smalw + urlS
        vs = 0

        if ovscore <= 2:
            # if the result is zero
            vs = ovscore * 10
            meterb.set(vs)
            text = "Score " + str(ovscore) + "/" + str(amount)
            meterb.configure(text=text, text_color="green", border_color="green")
            text_label13b.configure(text_color="green")
            savg = "Safe"
        elif ovscore > 2 and ovscore <= 4:
            # if the result is between 11 and 35
            vs = ovscore * 10
            meterb.set(vs)
            text = "Score " + str(ovscore) + "/" + str(amount)
            meterb.configure(text=text, text_color="yellow", border_color="yellow")
            savg = "Suspicious"
            text_label13b.configure(text_color="yellow")
        else:
            if ovscore <= 40:
                vs = ovscore + 40
            elif 40 < ovscore < 100:
                vs = ovscore + 10
            else:
                vs = ovscore
            meterb.set(vs)
            text = "Score " + str(ovscore) + "/" + str(amount)
            meterb.configure(text=text, text_color="red", border_color="red")
            savg = "Not safe"
            text_label13b.configure(text_color="red")

        if danger == 0:
            # if the result is zero
            text_label11b.configure(text_color="green")
        elif danger == 2 or danger == 3:
            # if the result is between 2 and 3
            text_label11b.configure(text_color="yellow")
        elif danger == 4 or danger == 5:
            # if the result is between 5 and 4
            text_label11b.configure(text_color="red")
        elif danger == 6:
            # if the result is 6
            text_label11b.configure(text_color="red")

        text_label11b.pack()
        text_label11b.configure(
            text="VIRUSTOTAL results: "
            + str(positives)
            + "/"
            + str(total_scans)
            + "\n the site is reported as a "
            + dangert
        )

        window.update()

        text_label13b.pack()
        text_label13b.configure(text="Overall results: " + savg)

        meterb.pack(pady=5)
        window.update()

        # opening the image
        im = Image.open(resource_path(os.path.dirname(sys.argv[0]) + ".\img.png"))
        button4b.configure(command=lambda: [im.show()])
        button4b.pack(pady=5, side="bottom")

        screenshot_qr = tk.CTkImage(im, size=(500, 375))
        screenshot_label_qr = tk.CTkLabel(
            frame4.tab("Screenshot"), text="", image=screenshot_qr
        )
        screenshot_label_qr.pack(pady=5)

        text_label9b.pack()
        text_label9b.configure(text="screenshot successfully loaded!")
        window.update()

        text_label17b.pack()
        text_label17b.configure(text="Scanning all Redirects...")

        window.update()

        redirects_handling_for_QR(Redirectedlinks)
        Redirectedlinks.clear()

        linksinpage = response2.json().get("lists").get("linkDomains")
        lnum = 1
        textboxb3.pack()
        for linkinpage in linksinpage:
            nums = str(lnum) + "- "
            textboxb3.configure(state="normal")
            textboxb3.insert(tk.END, nums + linkinpage + " \n")
            textboxb3.configure(state="disabled")
            global linkstoscan
            linkstoscan.append(linkinpage)
            lnum += 1

    done = True
    # a button if the user wants to search another link
    button2b.configure(
        command=lambda: [
            restore_window_for_QR(),
            button2b.pack_forget(),
            screenshot_label_qr.pack_forget(),
        ]
    )
    button2b.pack(pady=5, side="bottom")
    button3b.pack(pady=5, side="bottom")


def threading_scan_for_QR():
    if done:
        threading.Thread(target=display_content_for_QR()).join
    else:
        threading.Thread(target=display_content_for_QR()).start


def redirects_handling_for_QR(links):
    n = len(links)
    if n == 0:
        text_label17b.configure(text="No Redirects is found")
        text_label15b.configure(text="No Redirects is found")
        return

    for ls in links:
        if done:
            threading.Thread(target=scan_redirects_for_QR(ls, n)).join
        else:
            threading.Thread(target=scan_redirects_for_QR(ls, n)).start
        n = n - 1
    links.clear()
    text_label17b.configure(text="Scanning all Redirects is successful")
    text_label15b.configure(text="Scanning all Redirects is successful")


def scan_redirects_for_QR(ls, n):
    text_label15b.pack()
    # post the request to urlscan.io
    global urlSAPI
    headers = {
        "API-Key": urlSAPI,
        "Content-Type": "application/json",
    }
    data = {"url": ls, "visibility": "public"}
    response = requests.post(
        "https://urlscan.io/api/v1/scan/", headers=headers, data=json.dumps(data)
    )
    text_label15b.pack(pady=5)

    # post the request to virustotal
    global vTAPI
    urlV = "https://www.virustotal.com/vtapi/v2/url/scan"
    paramsV = {
        "apikey": vTAPI,
        "url": ls,
    }

    responseV = requests.post(urlV, data=paramsV)
    timeO = 0
    while responseV.status_code != 200:
        time.sleep(2)
        timeO += 2
        text_labelb.configure(text="Loading... just a few seconds...")
        window.update()
        responseV = requests.post(urlV, data=paramsV)
        if timeO >= 14:
            text_labelb.configure(text="Virustotal Scan is Unsuccessfull")
            done = True
            exit

    # if the urlscan.io response code is not 200
    if response.status_code != 200:
        text_label15b.configure(
            text="This link is blacklisted or invalid", text_color="red"
        )
        time.sleep(1)
        window.update()
        done = True
        exit

    # if the urlscan.io response code is 200
    else:
        scanID = responseV.json().get("scan_id")
        # get the uuid from the response
        x = response.json().get("uuid")
        text_label15b.configure(text="Scanning all redirects...")
        window.update()

        # load the progbar
        progbarb2.anchor("n")
        progbarb2.pack(pady=5)
        progbarb2.set(0)
        textboxb2.pack()

        # preforming the loading
        for i in range(499):
            time.sleep(0.015)
            progbarb2.start()
            progbarb2.stop()
            window.update()

        # getting the response from urlscan.io
        response2 = requests.get("https://urlscan.io/api/v1/result/" + x + "/")

        timeO = 0

        # if the response is not 200, wait
        while response2.status_code != 200:
            time.sleep(2)
            timeO += 2
            text_label15b.configure(text="Scanning all redirects... please wait...")
            window.update()
            response2 = requests.get("https://urlscan.io/api/v1/result/" + x + "/")
            if timeO >= 10:
                text_label15b.configure(text="URLScani.io Scan is Unsuccessfull")
                exit

        # if the scan is successfull
        text_label15b.configure(text="Scan is successfull")

        # get the response from virustotal
        urlV2 = "https://www.virustotal.com/vtapi/v2/url/report"
        paramsV2 = {
            "apikey": vTAPI,
            "resource": scanID,
        }
        responseV2 = requests.get(urlV2, params=paramsV2)
        timeO = 0
        while responseV2.status_code != 200:
            time.sleep(4)
            timeO += 4
            text_labelb.configure(text="Loading... just a few seconds...")
            window.update()
            responseV2 = requests.get(urlV2, params=paramsV2)
            if timeO >= 20:
                text_labelb.configure(text="Virustotal Scan is Unsuccessfull")
                exit

        verdict_info = response2.json().get("verdicts")
        is_malicious = verdict_info.get("overall").get("malicious")
        score = verdict_info.get("overall").get("score")
        malicious_total = verdict_info.get("engines").get("maliciousTotal")
        category = verdict_info.get("overall").get("categories")

        positives = responseV2.json().get("positives")
        total_scans = responseV2.json().get("total")

        textboxb.tag_config("safe", foreground="green")
        textboxb.tag_config("not", foreground="red")
        if score <= 0:
            # some websites shows score below 0 while being safe
            score = 0
            s = "Safe"
            tag = "safe"
        else:
            s = "Not safe"
            tag = "not"

        dataURL = (
            "URLSCAN.IO results: "
            + s
            + ", The URL is : "
            + str(score)
            + "% malicious  \n"
        )

        textboxb2.tag_config("safe", foreground="green")
        textboxb2.tag_config("msafe", foreground="#90EE90")
        textboxb2.tag_config("susp", foreground="yellow")
        textboxb2.tag_config("not", foreground="red")
        window.update()
        percentageV = (positives / total_scans) * 100
        if percentageV <= 0:
            # if the result is zero
            sv = "Safe"
            tagv = "safe"
        elif percentageV >= 1 and percentageV <= 10:
            # if the result is between 1 and 10
            sv = "Mostly safe"
            tagv = "msafe"
        elif percentageV >= 11 and percentageV <= 35:
            # if the result is between 11 and 35
            sv = "Suspicious"
            tagv = "susp"
        else:
            # if the result is more than 35
            sv = "Not safe"
            tagv = "not"

        dataV = (
            "VIRUSTOTAL results: "
            + sv
            + ", The URL is : "
            + str(math.floor(percentageV))
            + "% malicious  \n"
        )

        urlinfo = str(n) + ". " + str(ls) + " \n"
        textboxb2.configure(state="normal")
        textboxb2.insert(tk.END, urlinfo)
        textboxb2.insert(tk.END, dataURL, tags=tag)
        textboxb2.insert(tk.END, dataV, tags=tagv)
        textboxb2.configure(state="disabled")
        done = True
        window.update()


def handling_scan_all_links_for_qr():
    textboxb3.configure(state="normal")
    textboxb3.delete("1.0", tk.END)
    textboxb3.configure(state="disabled")
    textboxb3.pack_forget()
    global linkstoscan
    n = len(linkstoscan)
    n2 = 1
    if n == 0:
        text_label18b.configure(text="No other links were found")
        text_label19b.configure(text="No other links were found")
        return

    for ls in linkstoscan:
        if done:
            threading.Thread(target=scan_all_links_for_qr(ls, n, n2)).join
        else:
            threading.Thread(target=scan_all_links_for_qr(ls, n, n2)).start
        n = n - 1
        n2 += 1

    text_label18b.configure(text="Scanning all links is successful")
    text_label19b.configure(text="Scanning all links is successful")
    linkstoscan.clear()


def scan_all_links_for_qr(ls, n, n2):
    # post the request to urlscan.io
    global urlSAPI
    headers = {
        "API-Key": urlSAPI,
        "Content-Type": "application/json",
    }
    data = {"url": ls, "visibility": "public"}
    response = requests.post(
        "https://urlscan.io/api/v1/scan/", headers=headers, data=json.dumps(data)
    )

    # post the request to virustotal
    global vTAPI
    urlV = "https://www.virustotal.com/vtapi/v2/url/scan"
    paramsV = {
        "apikey": vTAPI,
        "url": ls,
    }

    responseV = requests.post(urlV, data=paramsV)

    timeO = 0

    while responseV.status_code != 200:
        time.sleep(4)
        timeO += 4
        text_label19b.configure(
            text="Loading... just a few seconds..." + " links to scan:" + str(n)
        )
        text_label19b.pack(pady=5)
        window.update()
        responseV = requests.post(urlV, data=paramsV)
        if timeO >= 24:
            text_label19b.configure(text="Virustotal Scan is Unsuccessfull")
            text_label18b.configure(text="Virustotal Scan is Unsuccessfull")
            text_label19b.pack(pady=5)
            done = True
            exit

    timeU = 0
    # if the urlscan.io response code is not 200
    if response.status_code != 200:
        urlinfo = str(n) + ". " + str(ls) + " \n"
        errormsg = "Error: This link is blacklisted or invalid \n"
        textboxb3.configure(state="normal")
        textboxb3.insert(tk.END, urlinfo)
        textboxb3.insert(tk.END, errormsg)
        textboxb3.configure(state="disabled")
        time.sleep(1)
        window.update()
        done = True
        return

    # if the urlscan.io response code is 200
    else:
        scanID = responseV.json().get("scan_id")

        # get the uuid from the response
        x = response.json().get("uuid")
        text_label19b.configure(
            text="Scanning all Links in page..." + " links to scan:" + str(n)
        )
        text_label19b.pack(pady=5)
        text_label18b.configure(
            text="Scanning all Links in page..." + " links to scan:" + str(n)
        )
        text_label18b.pack(pady=10)
        window.update()

        # load the progbar
        progbarb3.anchor("n")
        progbarb3.pack(pady=5)
        progbarb3.set(0)
        textboxb3.pack()

        # preforming the loading
        for i in range(499):
            time.sleep(0.035)
            progbarb3.start()
            progbarb3.stop()
            window.update()

        # getting the response from urlscan.io
        response2 = requests.get("https://urlscan.io/api/v1/result/" + x + "/")

        timeO = 0

        # if the response is not 200, wait
        while response2.status_code != 200:
            time.sleep(2)
            timeO += 2
            text_label19b.configure(text="Scanning all links in page... please wait...")
            window.update()
            response2 = requests.get("https://urlscan.io/api/v1/result/" + x + "/")
            if timeO >= 10:
                text_label19b.configure(text="Scan is Unsuccessfull")
                text_label18b.configure(text="Scan is Unsuccessfull")
                exit

        # get the response from virustotal
        urlV2 = "https://www.virustotal.com/vtapi/v2/url/report"
        paramsV2 = {
            "apikey": vTAPI,
            "resource": scanID,
        }
        responseV2 = requests.get(urlV2, params=paramsV2)
        timeO = 0
        while responseV2.status_code != 200:
            time.sleep(2)
            timeO += 2
            text_label19b.configure(text="Loading... just a few seconds...")
            window.update()
            responseV2 = requests.get(urlV2, params=paramsV2)
            if timeO >= 14:
                text_label19b.configure(text="Scan is Unsuccessfull")
                text_label18b.configure(text="Scan is Unsuccessfull")
                return

        verdict_info = response2.json().get("verdicts")
        is_malicious = verdict_info.get("overall").get("malicious")
        score = verdict_info.get("overall").get("score")
        malicious_total = verdict_info.get("engines").get("maliciousTotal")
        category = verdict_info.get("overall").get("categories")

        positives = responseV2.json().get("positives")
        total_scans = responseV2.json().get("total")

        textboxb.tag_config("safe", foreground="green")
        textboxb.tag_config("not", foreground="red")
        if score <= 0:
            # some websites shows score below 0 while being safe
            score = 0
            s = "Safe"
            tag = "safe"
        else:
            s = "Not safe"
            tag = "not"

        dataURL = (
            "URLSCAN.IO results: "
            + s
            + ", The URL is : "
            + str(score)
            + "% malicious  \n"
        )

        textboxb3.tag_config("safe", foreground="green")
        textboxb3.tag_config("msafe", foreground="#90EE90")
        textboxb3.tag_config("susp", foreground="yellow")
        textboxb3.tag_config("not", foreground="red")

        percentageV = (positives / total_scans) * 100
        if percentageV <= 0:
            # if the result is zero
            sv = "Safe"
            tagv = "safe"
        elif percentageV >= 1 and percentageV <= 10:
            # if the result is between 1 and 10
            sv = "Mostly safe"
            tagv = "msafe"
        elif percentageV >= 11 and percentageV <= 35:
            # if the result is between 11 and 35
            sv = "Suspicious"
            tagv = "susp"
        else:
            # if the result is more than 35
            sv = "Not safe"
            tagv = "not"

        dataV = (
            "VIRUSTOTAL results: "
            + sv
            + ", The URL is : "
            + str(math.floor(percentageV))
            + "% malicious  \n"
        )

        urlinfo = str(n2) + ". " + str(ls) + " \n"
        textboxb3.configure(state="normal")
        textboxb3.insert(tk.END, urlinfo)
        textboxb3.insert(tk.END, dataURL, tags=tag)
        textboxb3.insert(tk.END, dataV, tags=tagv)
        textboxb3.configure(state="disabled")
        done = True


def browse_image():
    file_path = filedialog.askopenfilename()
    if file_path:
        scan_qr_code(resource_path(file_path))


def scan_qr_code(image_path):
    image = cv2.imread(image_path)
    decoded_objects = decode(image)
    if decoded_objects:
        global qr_code_data
        qr_code_data = decoded_objects[0].data.decode("utf-8")
        qr_code_result.pack_forget()
        buttonb.pack_forget()
        qr_code_result.pack(pady=20, padx=80, side="left")
        qr_code_result.configure(text="LINK : " + qr_code_data)
        button1b.pack(pady=5, padx=10, side="left")
        button1b.configure(
            command=lambda: [button1b.pack_forget(), threading_scan_for_QR()]
        )
    else:
        qr_code_result.configure(text="No QR Code found in the image")


def find_pdfs_in_folder():
    global pdf_docs
    pdf_docs = []
    folder_path = resource_path(os.path.dirname(sys.argv[0]) + "\pdfs")

    try:
        pdf_search = Path(resource_path(folder_path)).glob("*.pdf")
    except:
        messagebox.showerror(
            "Pdf files Eror",
            "Error: Unable to find pdf files",
        )
        exit()
    for pdf_path in pdf_search:
        pdf_docs.append(str(pdf_path.absolute()))
    return pdf_docs


def get_pdf_text(pdf_docs):
    text = ""
    for pdf in pdf_docs:
        pdf_reader = PdfReader(resource_path(pdf))
        for page in pdf_reader.pages:
            text += page.extract_text()
    return text


def get_text_chunks(text):
    text_splitter = CharacterTextSplitter(
        separator="\n", chunk_size=1000, chunk_overlap=200, length_function=len
    )
    chunks = text_splitter.split_text(text)
    return chunks


def create_vectorstore(text_chunks):
    global api_key
    embeddings = OpenAIEmbeddings(openai_api_key=api_key)
    global vectorstore
    vectorstore = FAISS.from_texts(texts=text_chunks, embedding=embeddings)


def create_conversation_chain():
    global api_key
    llm = ChatOpenAI(openai_api_key=api_key)
    memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)
    global conversation_chain
    conversation_chain = ConversationalRetrievalChain.from_llm(
        llm=llm, retriever=vectorstore.as_retriever(), memory=memory
    )


def handle_user_input():
    user_question = user_input.get()
    if not user_question:
        return

    # Clear the answer_text widget to avoid duplication
    conversation_text.configure(state="normal")
    conversation_text.delete("1.0", tk.END)
    conversation_text.insert(tk.END, "Loading...\n")
    conversation_text.configure(state="disabled")
    window.update()

    def question_worker():
        response = conversation_chain({"question": user_question})
        chat_history = response["chat_history"]

        conversation_text.configure(state="normal")
        conversation_text.delete("1.0", tk.END)
        conversation_text.configure(state="disabled")

        for i, message in enumerate(chat_history):
            if i % 2 == 0:
                conversation_text.configure(state="normal")
                conversation_text.insert(tk.END, f"User: {message.content}\n")
                conversation_text.configure(state="disabled")
            else:
                conversation_text.configure(state="normal")
                conversation_text.insert(tk.END, f"Bot: {message.content}\n")
                conversation_text.configure(state="disabled")

            conversation_text.configure(state="normal")
            conversation_text.insert(tk.END, "\n")
            conversation_text.configure(state="disabled")

    threading.Thread(target=question_worker).start()


def process_pdf():
    def process_pdf_worker():
        find_pdfs_in_folder()
        raw_text = get_pdf_text(pdf_docs)
        text_chunks = get_text_chunks(raw_text)
        create_vectorstore(text_chunks)
        create_conversation_chain()
        try:
            send_button.pack(pady=10)
            window.update
        except:
            messagebox.showerror(
                "ChatBot Eror",
                "Error: program was closed before fully loading the pdf files.",
            )
            exit()

    threading.Thread(target=process_pdf_worker).start()
    global done
    done = True


# creating the main window
window = tk.CTk()
window.title("url scanner")
window.geometry("1200 x 720")

# the kau logo images
image = Image.open(resource_path("KAU_logo.png"))
image = tk.CTkImage(image, size=((75, 95)))
image_label = tk.CTkLabel(window, text="", image=image)
image_label.pack(anchor="nw", pady=5, padx=25, side="left")
# the cs logo image
image2 = Image.open(resource_path("CS Whte Logo (1).png"))
image2 = tk.CTkImage(image2, size=((120, 50)))
image_label2 = tk.CTkLabel(window, text="", image=image2)
image_label2.pack(anchor="ne", pady=25, padx=25, side="right")

# creating the main frame and the tabs
frame0 = tk.CTkTabview(window, width=800, height=660, fg_color="#252526")
frame0.pack(padx=10, side="top")
frame0.pack_propagate(False)
frame0.add("URL")
frame0.add("QR")
frame0.add("CHAT")

# frame 1 tab 1
frame1 = tk.CTkFrame(frame0.tab("URL"), width=600, height=100)
frame1.pack(pady=5, padx=10, side="top")
frame1.pack_propagate(False)

# frame 2 tab 1
frame2 = tk.tabview = tk.CTkTabview(frame0.tab("URL"), width=600, height=490)
frame2.pack(pady=5, padx=10)
frame2.pack_propagate(False)
frame2.add("Results")
frame2.add("Redirects")
frame2.add("Details")
frame2.add("Links")
frame2.add("Screenshot")

# frame 3 tab 2
frame3 = tk.CTkFrame(frame0.tab("QR"), width=600, height=100)
frame3.pack(pady=5, padx=10, side="top")
frame3.pack_propagate(False)

# frame 4 tab2
frame4 = tk.tabview = tk.CTkTabview(frame0.tab("QR"), width=600, height=490)
frame4.pack(pady=5, padx=10)
frame4.pack_propagate(False)
frame4.add("Results")
frame4.add("Redirects")
frame4.add("Details")
frame4.add("Links")
frame4.add("Screenshot")

# to help with threads
global done
done = False

# first label
text_label0a = tk.CTkLabel(frame1, text="URL Scanner", font=("Arial", 25))
text_label0a.pack(pady=5)

# creating and placing the widgets
entrya = tk.CTkEntry(frame1, width=500, placeholder_text="Enter your link")
entrya.pack(pady=5, padx=10, side="left")

# create the button
buttona = tk.CTkButton(
    frame1,
    text="Scan",
    height=28,
    width=60,
    command=lambda: [buttona.pack_forget(), threading_scan()],
)
buttona.pack(pady=5, padx=10, side="left")

# the progress bar
progbara = tk.CTkProgressBar(
    frame2.tab("Results"),
    orientation="horizontal",
    determinate_speed=0.1,
    height=10,
    width=400,
)

# the second progress bar
progbara2 = tk.CTkProgressBar(
    frame2.tab("Redirects"),
    orientation="horizontal",
    determinate_speed=0.1,
    height=10,
    width=400,
)

# the third progress bar
progbara3 = tk.CTkProgressBar(
    frame2.tab("Links"),
    orientation="horizontal",
    determinate_speed=0.1,
    height=10,
    width=400,
)


# text labels and text box in the first tab
text_labela = tk.CTkLabel(frame2.tab("Results"), text="")
text_label5a = tk.CTkLabel(frame2.tab("Results"), text="")
text_label6a = tk.CTkLabel(frame2.tab("Results"), text="")
text_label7a = tk.CTkLabel(frame2.tab("Results"), text="")
text_label8a = tk.CTkLabel(frame2.tab("Results"), text="")
text_label9a = tk.CTkLabel(frame2.tab("Results"), text="")
text_label10a = tk.CTkLabel(frame2.tab("Results"), text="")
text_label11a = tk.CTkLabel(frame2.tab("Results"), text="")
text_label12a = tk.CTkLabel(frame2.tab("Results"), text="")
text_label13a = tk.CTkLabel(frame2.tab("Results"), text="")
text_label14a = tk.CTkLabel(frame2.tab("Details"), text="")
text_label15a = tk.CTkLabel(frame2.tab("Redirects"), text="")
text_label17a = tk.CTkLabel(frame2.tab("Results"), text="")
textboxa = tk.CTkTextbox(frame2.tab("Details"), width=500, height=350)
textboxa.configure(state="disabled")
textboxa2 = tk.CTkTextbox(frame2.tab("Redirects"), width=500, height=350)
textboxa2.configure(state="disabled")
textboxa3 = tk.CTkTextbox(frame2.tab("Links"), width=500, height=350)
textboxa3.configure(state="disabled")
text_label18a = tk.CTkLabel(frame2.tab("Results"), text="")
text_label19a = tk.CTkLabel(frame2.tab("Links"), text="")
screenshot_label = tk.CTkLabel
screenshot = tk.CTkImage
# the meter
metera = Meter(
    frame2.tab("Results"),
    radius=135,
    start=0,
    end=455,
    border_width=1,
    fg="#303234",
    text_color="white",
    start_angle=90,
    end_angle=-360,
    text_font="DS-Digital 10",
    scale_color="#303234",
    axis_color="grey",
    needle_color="black",
    scroll=False,
    major_divisions=455,
)
metera.set_mark(0, 20, "green")
metera.set_mark(21, 40, "yellow")
metera.set_mark(41, 455, "red")
metera.set(0)

# the buttons
button2a = tk.CTkButton(
    frame2.tab("Results"),
    text="Clear",
    command=lambda: [
        restore_window(),
        button2a.pack_forget(),
    ],
)

button3a = tk.CTkButton(
    frame2.tab("Results"),
    text="Scan all links",
    command=lambda: [button3a.pack_forget(), handling_scan_all_links()],
)

button4a = tk.CTkButton(frame2.tab("Screenshot"), text="Open Screenshot")

linkstoscan = []

########################################### TAB 2 #######################################################################

# first label
text_label0b = tk.CTkLabel(frame3, text="QR Code Scanner", font=("Arial", 25))
text_label0b.pack(pady=5)

# creating and placing the label
qr_code_result = tk.CTkLabel(frame3, text="", wraplength=300)
qr_code_result.pack()

# create the buttons
buttonb = tk.CTkButton(
    frame3, text="Select Image", height=28, width=60, command=browse_image
)
buttonb.pack(pady=5, padx=50)
button1b = tk.CTkButton(frame3, text="Scan", height=28, width=60)

# the progress bar
progbarb = tk.CTkProgressBar(
    frame4.tab("Results"),
    orientation="horizontal",
    determinate_speed=0.1,
    height=10,
    width=400,
)

# the second progress bar
progbarb2 = tk.CTkProgressBar(
    frame4.tab("Redirects"),
    orientation="horizontal",
    determinate_speed=0.1,
    height=10,
    width=400,
)

# the third progress bar
progbarb3 = tk.CTkProgressBar(
    frame4.tab("Links"),
    orientation="horizontal",
    determinate_speed=0.1,
    height=10,
    width=400,
)


# text labels
text_labelb = tk.CTkLabel(frame4.tab("Results"), text="")
text_label5b = tk.CTkLabel(frame4.tab("Results"), text="")
text_label6b = tk.CTkLabel(frame4.tab("Results"), text="")
text_label7b = tk.CTkLabel(frame4.tab("Results"), text="")
text_label8b = tk.CTkLabel(frame4.tab("Results"), text="")
text_label9b = tk.CTkLabel(frame4.tab("Results"), text="")
text_label10b = tk.CTkLabel(frame4.tab("Results"), text="")
text_label11b = tk.CTkLabel(frame4.tab("Results"), text="")
text_label12b = tk.CTkLabel(frame4.tab("Results"), text="")
text_label13b = tk.CTkLabel(frame4.tab("Results"), text="")
text_label14b = tk.CTkLabel(frame4.tab("Details"), text="")
text_label15b = tk.CTkLabel(frame4.tab("Redirects"), text="")
text_label17b = tk.CTkLabel(frame4.tab("Results"), text="")

textboxb = tk.CTkTextbox(frame4.tab("Details"), width=500, height=350)
textboxb.configure(state="disabled")
textboxb.pack()
textboxb2 = tk.CTkTextbox(frame4.tab("Redirects"), width=500, height=350)
textboxb2.configure(state="disabled")
textboxb3 = tk.CTkTextbox(frame4.tab("Links"), width=500, height=350)
textboxb3.configure(state="disabled")
text_label18b = tk.CTkLabel(frame4.tab("Results"), text="")
text_label19b = tk.CTkLabel(frame4.tab("Links"), text="")
screenshot_label_qr = tk.CTkLabel
screenshot_qr = tk.CTkImage

# the meter
meterb = Meter(
    frame4.tab("Results"),
    radius=135,
    start=0,
    end=455,
    border_width=1,
    fg="#303234",
    text_color="white",
    start_angle=90,
    end_angle=-360,
    text_font="DS-Digital 10",
    scale_color="#303234",
    axis_color="grey",
    needle_color="black",
    scroll=False,
    major_divisions=455,
)
meterb.set_mark(0, 20, "green")
meterb.set_mark(21, 40, "yellow")
meterb.set_mark(41, 455, "red")
meterb.set(0)

# the buttons
button2b = tk.CTkButton(
    frame4.tab("Results"),
    text="Clear",
    command=lambda: [
        restore_window_for_QR(),
        button2b.pack_forget(),
    ],
)
button3b = tk.CTkButton(
    frame4.tab("Results"),
    text="Scan all links",
    command=lambda: [button3b.pack_forget(), handling_scan_all_links_for_qr()],
)
button4b = tk.CTkButton(frame4.tab("Screenshot"), text="Open Screenshot")
linkstoscan = []


########################################### TAB 3 #######################################################################

# first label
text_label0c = tk.CTkLabel(
    frame0.tab("CHAT"), text="Cyber Security ChatBot", font=("Arial", 25)
)
text_label0c.pack(pady=5)

# the chatbox
conversation_text = tk.CTkTextbox(
    frame0.tab("CHAT"), wrap="word", width=600, height=400
)
conversation_text.pack(padx=10, pady=10)
conversation_text.configure(state="disabled")

# entry for user input
user_input = tk.CTkEntry(frame0.tab("CHAT"), width=200)
user_input.pack(padx=10, pady=10)

# to store the pdf
pdf_docs = []
vectorstore = None
conversation_chain = None

# the button to send the message
send_button = tk.CTkButton(
    frame0.tab("CHAT"),
    text="Send",
    command=lambda: [handle_user_input(), user_input.delete(0, "end")],
)

# the exit button
button3 = tk.CTkButton(window, text="Exit", command=window.destroy)
button3.pack(side="bottom", pady=5)

process_pdf()
# running the main loop
window.mainloop()
