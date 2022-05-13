---
title: Introduction To Windows Active Directy 
date: 2022-03-10
categories: [active-directory]
tags: [windows, powershell, powerview, active-directory]     # TAG names should always be lowercase
---

# **Task 1. Introduction**
###  Component

- Domain Controllers
- Forests, Trees, Domains
- Users + Groups 
- Trusts
- Policies 
- Domain Services

### Why use it?

1. it allows everyone to basically login to any PC in the network. and still get only the files he own.

	

# **Task 2. Domain Controller**

domain controller --> a windows server that has adds installed, the its promoted to a domain controller in the forest. So basically this is like the godfather of everything inside the AD. Some of its uses are: 

1. holds adds data-store 
2. authentication and authorization 
3. replicate updates from other domains
4. allow admin access to manage the domain resources.



### ADDS Data-store

Holds the databases and processes needed to store and manage directory information, such as users, groups, services. Some of the data is stores:

1. NTDS.dit - a db that contains all of the information of an AD as well as password hashes of the domain users.
2. stored by all those sensitive infos at %SystemRoot%\NTDS
3. all those files are only accessible by the domain controller (no one can see those files in AD network)





# **Task 3. Forest, Tree, Domain**

Forest --> A container that holds all of the other bits and pieces of the network together. So basically this is like host in docker when u use --net=host option.
Its not a physical rather a figurative thing. Forest connect between trees and domains in the network.

![What is an Active Directory Forest?](https://info.varonis.com/hubfs/Imported_Blog_Media/domain-forest@2x.png?hsLang=en)



As we can see from the above image. Forest is just a connection between 2 or more domains. The Forest consist of the following

1. Trees - a hierarchy of domains in ADDS
2. Domains - Used to group and manage objects
3. Organizational Units - Containers for groups, computers, users, printers etc.
4. Trust - Allow users to access resources in the other domain.(by using forest we can build this trust. also the attack that china used again Us navy thats what they use)
5. Object - Users, Groups, Printers, Computers, Shares.
6. Domain service - DNS Serve, LLMNR, IPv6
7. Domain Schema - Rules for object creation



# **Task 4. Users + Groups**

### Users Overview

Users and groups --> are inside of an AD, the domain controller creates 2 dummy users for ya (Admin, Guest). its up to you change or add some other users. typically there's 4 type of users in an AD but u can see more. those users are: 

1. Domain admins - basically root in linux(this group are the only group with access to domain controller, as we talked about this earlier)
2. Service Accounts (can also be domain admins) - mostly people don't use them, they're their for system service, like mysql and so on.
3. Local admin - They can access/modify local users stuff, but they can't do anything on the domain controller. 
4. Domain Users - Literally everything single motherfucker is here. they can login to any machine with their user + pass, but they cant even view other users stuff. (cuz why would they be allowed)

### Group Overview

Just like how stuff are in linux,. Group make it easy to give permission users and objects,. literal types of AD groups

1. Security Groups - We use this type of groups to give permission to a large number of users.
2. Distribution Groups - this group use to specify email distribution list. (As an attacker this group is pretty useless to us, may in enumeration we use it)

#### Default Security Groups

- Domain Controllers - all domain controllers in a domain
- Domain Guest - all guest
- Domain users - everyone
- Domain Computers - all workstations and servers joined to the domain
- Domain admins - Designated admin of the domain
- Enterprise admins - Designated admin of the enterprise
- Schema admins - Designated admin of the schema
- DNS admins - DNS admin group
- DNS update proxy - DNS clients who are permitted to perform some dynamic updates on behalf of some other clients (such as dhcp)
- Allowed RODC Password Replication Group - Members in this group can have their passwords replicated to all read-only domain controllers in the domain
- Group Policy Creator Owners - Members in this group can modify group policy for the domain
- Denied RODC Password Replication Group - Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
- Protected Users - Members of this group are afforded additional protections against authentication security threats
- Cert Publishers - Members of this group are permitted to publish certificates to the directory
- Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the domain
- Enterprise Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the enterprise
- Key Admins - Members of this group can perform administrative actions on key objects within the domain
- Enterprise Key Admins - Members of this group can perform administrative actions on key objects within the forest
- Cloneable Domain Controllers - Members of this group that are domain controllers may be cloned
- RAS and IAS Servers - Servers in this group can access remote access properties of users





# **Task 5. Trust + Policies**

Trust and Policies are set of rules that everyone in a domain must follow to main security. such rules can be how to communicate with one another in the domain or with someone outside of the domain. literally how external or internal forest should communicate.



### Domain Trust Overview

So Trust most of the time we use it inside a forest showing how domains should communicate. in some environments trust can be extended out to the external domain. even external forest in some cases.

![img](https://i.imgur.com/4uGI3bF.png)

There are 2 types of trust that determined how the domains communicate.

1. Directional - The direction of the trust flows from a trusting domain to a trusted domain
2. Transitive - The trust relationship expands beyond just two domains to include other trusted domains

When attacking AD we can abuse some trust to move laterally throughout the network



### Domain Policies Overview

Policies are a very big part of Active Directory, they dictate how the server operates and what rules it will and will not follow. You can think of domain policies like domain groups, except instead of permissions they contain rules, and instead of only applying to a group of users, the policies apply to a domain as a whole. They simply act as a rulebook for Active Directory that a domain admin can modify and alter as they deem necessary to keep the network running smoothly and securely. Along with the very long list of default domain policies, domain admins can choose to add in their own policies not already on the domain controller, for example: if you wanted to disable windows defender across all machines on the domain you could create a new group policy object to disable Windows Defender. The options for domain policies are almost endless and are a big factor for attackers when enumerating an Active Directory network. I'll outline just a few of the many policies that are default or you can create in an Active Directory environment: 

- Disable Windows Defender - Disables windows defender across all machine on the domain
- Digitally Sign Communication (Always) - Can disable or enable SMB signing on the domain controller



# **Task 6. Directory DS + Authentication**

The core function of and AD network; they enable management of the domain, security certificates, LDAPs etc. This is how domain decided what it wants todo and what service it wants to provide for the domain

### Domain Service Overview

They just bunch of service provided my domain controllers to the rest of domain or the tree. below are some default services in and AD

- LDAP - Lightweight Directory Access Protocol; provides communication between applications and directory services
- Certificate Services - allows the domain controller to create, validate, and revoke public key certificates
- DNS, LLMNR, NBT-NS - Domain Name Services for identifying IP hostnames

### Domain Authentication Overview

The most important part of an AD, as well as the most vulnerable part. but that depends on which typa authentication protocol we set/use. there are 2 main authentication in AD.

1. NTLM - Default windows authentication protocol uses in encrypted challenge/ response protocol
2. Kerberos - Default authentication service for AD. this thing uses ticket-granting tickets and service tickets to authenticate users and give users to other resources across the domain.

This are the access point of an attacker in AD environment as they're the most vulnerable piece.


# **Task 7. AD in Cloud**

Everyone is moving toward cloud its cheaper, and way secure than on-premise physical AD.. and well it just work. 



### Azure AD Overview

Acts a middle man to your network. allow users to login using its own services then they can proceed with their usual stuff just like in normal physical AD.

![img](https://i.imgur.com/J8q52i2.png)



### Some Comparison

![image-20220319211923448](/assets/img/active-dir/comparison.png)



# **Task 8. Hands-On Lab**

### connecting to the server

```bash
xfreerdp /u:Administrator /p:password123@ /cert:ignore /v:10.10.246.66 /workarea
```

### PowerView Setup

```bash
cd Downloads
powershell -ep bypass # load a powershell with execution policy
. .\PowerView.ps1 # Import the powerview module
```

![image-20220319213707640](/assets/img/active-dir/powerview_setup.png)

### Lab Overview

#### Get all os on the domain

```powershell
Get-NetComputer -fulldata | select operatingsystem # Get all os on the domain
```

![image-20220319214048060](/assets/img/active-dir/get_all_os_domain.png)

#### Get all users on the domain 

```powershell
Get-NetUser | select cn
```


### Flags

<b>1.</b> `Null` 

<b>2.</b> `Admin2`

![image-20220319220552930](/assets/img/active-dir/flag_2.png)

<b>3.</b> `windows 10 enterprise evaluation`

![image-20220319220505939](/assets/img/active-dir/flag_3.png)

<b>4.</b> `Hyper-V administrators`

![image-20220319215251180](/assets/img/active-dir/flag_4.png)

<b>5.</b> `5/13/2020 8:26:58`

![image-20220319220100166](/assets/img/active-dir/flag_5.png)

# **Resources**
``` html
powerview: https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
room link: https://tryhackme.com/room/activedirectorybasics
```