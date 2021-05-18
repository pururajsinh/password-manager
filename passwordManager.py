#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Mon Nov 25 01:26:09 2019

@author: pururajsinh
"""
#==============================================================================
# Password Manager is a program that makes use of one master password for managing 
# all the passwords for different services used in day to day activities involving
# social media, payment gateways and so on...
# In this manager Fernet library was used for the purpose of generation of key 
# and for the purpose of encryption and decryption.
#==============================================================================
import random
import pickle
import os
from cryptography.fernet import Fernet

head = '____             __   __  __\n' \
    + "|  _ \  ____    | |  |  \/  | __ _ _ __  \n" \
    + "| |_)| |  _`|  _|_|_ | |\/| |/  _` | '_ \ \n" \
    + "| |_)| | (_||  |__ | | |  | || (_| | | | |\n" \
    + "|____/ |__,_|_  |_|  |_| |_||\___| |_| |_|\n"
    
print(head)

info = {}
minfo ={}
kinfo ={}
keylabel = "key"
label = "password"

s = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%^&*()?"

# function created that will run until user types no on asking a "Do you want to
# continue". The function checks for the service in file namemd "encryptedpasswords.txt"
# if a service exist then its passwords is displayed in the terminal and if the service
# doesnot exist , a new service is created and the its password is been displayed 
def servicePassword(f):
    info = {}
    approval = 1
    while(approval):
        service = raw_input("Enter The Service: ")
        # checking if the file exist by checking the size of file 
        # (this is checked only for the first service)
        if not os.path.isfile("encryptedpasswords.txt"):
          print("Creating a new Service")
        # creating a password for the entered service
          password = "".join(random.sample(s, 12))
        # encrypt the password and then write the encrypted password in binary format in the file
          encryptPassword = f.encrypt(password)
          info[service] = encryptPassword 
          with open("encryptedpasswords.txt","wb") as fileWrite:
              pickle.dump(info, fileWrite) 
        # load the variable with content of the file, decrypt it and show it on the terminal
              epassword =info[service]
              dpassword = f.decrypt(epassword)
              print(service + " : " + dpassword)
        # the file already existed and thus loading the contents of file in a variable
        # check if service is already present in the variable
        else:
            with open("encryptedpasswords.txt", "rb") as fileRead:
                info = pickle.load(fileRead)    
            if(service in info):
        # service is found in the variable and hence decrypt the password of the service
        # present in the variable and show the service along the password int terminal.
                epassword =info[service]
                dpassword = f.decrypt(epassword)
                print(service + " : " + dpassword)
                 
            else:
                # if service not found in the existing file, create a new service and a password for it
                print("Creating a new Service")    
                password = "".join(random.sample(s, 12))
                # created a password of 12 digits for the service and encrypt password.
                encryptPassword = f.encrypt(password)
                info[service] = encryptPassword 
                with open("encryptedpasswords.txt","wb") as fileWrite:
                    pickle.dump(info, fileWrite)
                with open ("encryptedpasswords.txt", "rb") as fileRead:
                    info = pickle.load(fileRead)
                    epassword =info[service]
                # load the encrypted password from the file, decrypt it and print it along with the service
                    dpassword = f.decrypt(epassword)
                    print(service + " : " + dpassword)
        approval = raw_input("Do you Wish to continue? ")
        # if the user does not wishes to add new services or check passwords of previous services, user
        # can type "no" and the program will be terminated.
        if("no" in approval):
            break
# check if the file of masterket exists or not. If not create a file, create a master key, add master key to the file
# when the program is executed for the first time, the file is created and key is stored in it unless the file is deleated.            
if not os.path.isfile('masterkey.txt'):
        k = Fernet.generate_key()
        f = Fernet(k)
        kinfo[keylabel] = k
        with open("masterkey.txt","wb") as mfileWriteKey:
            pickle.dump(kinfo, mfileWriteKey)
#if file exists that means key also exist as mentioned in the previous comment. Thus use the key to generate instant of "Fernate"
# using this instance, we will encrypt and decrypt the files. This instance is passend in the calling function. 
else:
    with open("masterkey.txt", "rb") as mfileReadKey:
        kinfo = pickle.load(mfileReadKey)
        f = Fernet(kinfo[keylabel])
# This will take input of master password and check if "masterPassword.txt" exists or not if not, the executer is a new user and thus 
# creates a file, encrypts the master password and saves it. This master password is used for user authentication.
masterPassword = raw_input("Enter Master Password: ")
if not os.path.isfile('masterPasswordfile.txt'):
    emasterPassword = f.encrypt(masterPassword)
    minfo[label] = emasterPassword
    with open("masterPasswordfile.txt","wb") as mfileWrite:
        pickle.dump(minfo, mfileWrite)
        print("New User Created")
        servicePassword(f)
    
# If the file exists, retrived the masterpassword from the file, decrypt it and check if the entered password matches the retrived password.
else:
    with open("masterPasswordfile.txt", "rb") as mfileRead:
        minfo = pickle.load(mfileRead)
        dmasterPassword = f.decrypt(minfo[label])
    if(masterPassword in dmasterPassword):
        print("successfully validated user")
        
        servicePassword(f)
    else:
        print("Secure Login Failed, In valid Passoword")
        exit
