# Penetration-testing-lab-with-Kali-Linux-on-Metasploitable-2
## Purpose
The aim of this lab is to experience ethical hacking in a virtual environment composed of two virtual machines: an attacker machine running Kali Linux (an Advanced Penetration Testing Linux distribution used for Penetration Testing) and a victim host running Metasploitable 2 (an intentionally vulnerable Ubuntu Linux virtual machine designed for testing common vulnerabilities).
In this lab, I will:
* Lean the penetration testing methodology.
* Conduct port scanning and services enumeration on the target host.
* Brute force the login page of a web application.
* Exploit a command injection vulnerability on a vulnerable web server and gain an unprivileged access through a reverse shell execution.
* Escalate privilege and become root user on the vulnerable machine.
* Install a backdoor on the compromised host to maintain access.
* Hide traces on the victim system by installing and configuring a rootkit.

---

## 🛠️ Lab Setup
Two virtual hosts running Linux operating system are required to achieve this lab. The first is the attacker machine and is running **Kali Linux** (an Advanced Penetration Testing Linux distribution used for Penetration Testing). The second is the victim machine running **Metasploitable 2** (an intentionally vulnerable Ubuntu Linux virtual machine designed for testing common vulnerabilities). The two network adapters of these machines are attached to a **NAT Network**, so that they can communicate to each other and talk to outside (main host, local network, and internet).

![Network Architecture](/images/network.png)

---


### ⚙️ Lab Setup: Instaling Kali linux:

#### Step 1: Download the Pre-Built VM Image

1.  Navigate to the official Kali Linux virtual machine download page:
    * **Link:** `https://www.kali.org/get-kali/#kali-virtual-machines`
2.  Scroll to the **Pre-built VM** section.
3.  Select the download option corresponding to your virtualization platform (e.g., **VirtualBox**).
4.  Click **Download** to obtain the compressed file (usually a `.7z` or `.zip` archive).
5.  **Extract** the contents of the downloaded archive file. This will yield the `.vbox` and `.vdi` files for the VM.

#### Step 2: Import the VM into VirtualBox

1.  Open the **VirtualBox Manager**.
2.  Import the virtual machine using one of the following methods:
    * Click the **Add** machine icon (usually a blue `+` sign) and select the extracted **`.vbox`** configuration file.
    * Alternatively, **double-click** the extracted **`.vbox`** file directly from your file explorer.
3.  The Kali Linux VM instance will be automatically added to the VirtualBox list.



---

### 🎯 Lab Setup: Installing Metasploitable 2 VM

Metasploitable 2 is downloaded as a virtual hard disk file (`.vmdk`) that must be manually configured into a new VirtualBox machine.

#### Step 1: Download the VM Disk Image

1.  Navigate to the Metasploitable project files page on SourceForge:
    * **Link:** `https://sourceforge.net/projects/metasploitable/files/Metasploitable2/`
2.  Click the **Download** button for the latest Metasploitable 2 release.
3.  The file will download in a **ZIP format** and contains the virtual hard disk file (**.vmdk**).
4.  **Extract** the contents of the ZIP archive.

#### Step 2 Create and Configure the VM

1.  Open the **VirtualBox Manager**.
2.  Click the **New** button to create a new Virtual Machine.
3.  Configure the initial settings in the pop-up window:
    * **Name:** Choose a descriptive name (e.g., `Metasploitable-2`).
    * **Folder:** Leave as the default path unless a custom location is desired.
    * **Type:** **Linux**
    * **Version:** **Other Linux (64-bit)**
4.  Set the **Memory size (RAM)**. The recommended minimum is **512 MB**.
5.  In the **Hard Disk** section, select the option: **Use an existing virtual hard disk file**.
6.  Click the folder icon, then browse to and select the extracted **`.vmdk`** file from the Metasploitable 2 archive.
7.  Click **Create** to finalize the VM creation.

The Metasploitable 2 instance is now ready in the VirtualBox list.


### 🛠️ Lab Setup: Creating a Custom NAT Network

This procedure details the steps for configuring a dedicated **NAT Network** within your virtualization software (e.g., VirtualBox). This isolates your Kali Linux and Metasploitable 2 Virtual Machines (VMs) in a private network, facilitating safe and realistic penetration testing without exposing the lab environment to your host machine's primary network or the wider internet.

---

#### Step 1: Configure the Custom NAT Network

Follow these steps to define a new, isolated virtual network that both VMs will share.

1.  Navigate to the **VirtualBox Manager** application.
2.  Go to **File** $\rightarrow$ **Tools** $\rightarrow$ **Network Manager** (or simply press `Ctrl + H`).
3.  Select the **NAT Networks** tab.
4.  Click the **Create** icon (usually a **+** sign).
5.  A new NAT Network will be created with default settings.
    * **Recommendation:** **Rename** the network (e.g., `PenTest-Lab-Net`) for clear identification.
6.  Click **OK** to save and close the Network Manager.


#### Step 2: Assign VMs to the Custom NAT Network

You must configure both the Kali Linux and Metasploitable 2 VMs to use the network created in Step 1.

1.  In the VirtualBox Manager, select the **Kali Linux** VM.
2.  Click the **Settings** icon.
3.  Navigate to the **Network** category.
4.  In the **Adapter 1** tab:
    * Set the **Attached to:** option to **NAT Network**.
    * From the **Name** dropdown menu, select the custom network you created (e.g., `PenTest-Lab-Net`).
5.  Click **OK** to apply the settings for the Kali Linux VM.
6.  **Repeat steps 1 through 5** for the **Metasploitable 2** VM, ensuring it is also set to the *same* **NAT Network**.

## Penetration Testing Methodology

### Step 1: Information gathering

This step focuses on gathering essential network configuration data from the attacker machine (Kali Linux) using standard command-line tools. This information is crucial for planning subsequent penetration testing activities.

1.  **Start** both the **Kali Linux** and **Metasploitable 2** Virtual Machines.Log in to the **Kali Linux** attacker machine.(By default username: kali & password: kali) and open a terminal window and execute the following commands:

    * **To find the IP Address and Netmask:**
        ```bash
        ifconfig
        ```

    * **To find the Default Gateway Address:**
        ```bash
        netstat -r
        ```
  ![Kali Linux' ip](/images/ifconfig.png)
  ![Getway Address](/images/netstat_r_getway.png)

   In our case, the IP address of the attacker machine is 10.0.2.15, the IP network address is 10.0.2.0/24
   and the gateway IP address is 10.0.2.1.

2. Do a **Host Discovery Scan** on the entire target subnet to determine which hosts are currently online.
   
   From the terminal of the Kali Linux attacker machine, execute the following `nmap` command. We use the IP network address identified previously.

   ```bash
   nmap -sn 10.0.2.0/24
   ```
   ![Host Discovery](/images/host_discovery.png)
   
   Looking at the VirtualBox documentation, we can confirm the default address allocations for a custom NAT network, which helps identify the Metasploitable 2 target:

   | IP Address | Role in NAT Network |
   | :--- | :--- |
   | `10.0.2.2` | Host's Loopback Address |
   | `10.0.2.3` | DHCP Server |
   | `10.0.2.1` | Default Gateway |
   
   Since your `nmap` scan results confirmed:
   * **Attacker (Kali) Machine IP:** `10.0.2.15`
   * **Default Gateway IP:** `10.0.2.1`
   
   By elimination, the remaining active host found in the scan, **`10.0.2.4`**, is confirmed to be the **Target Machine (Metasploitable 2)**.

3. Do a **Service Discovery** on open ports after having successfully identified the target host's IP address , the next crucial phase is to perform a **port scan**. This determines which network services are running and accessible on the target machine.
   
   From the Kali Linux terminal, execute the following `nmap` command using the target IP address (e.g., `10.0.2.4`):

   ```bash
   sudo nmap -sS 10.0.2.4
   ```
   ![Service Discovery](/images/service_discovery.png)

   The scan output confirms 23 open ports. These ports host various network services (e.g., FTP, SSH, HTTP, MySQL, Telnet) which are often configured with known, exploitable vulnerabilities.

### Step 2: Information gathering

   After obtaining a preliminary overview of the target, the attacker moves further to know the exact services running on the target system (including types and versions) and other information such as users, shares, and DNS entries. Enumeration prepares a clearer blueprint of the target.

1.  Nmap has a special flag to activate aggressive detection, namely `-A`, which enables **OS detection** ($-O$), **version detection** ($-sV$), **script scanning** ($-sC$), and **traceroute** ($--traceroute$). This mode sends more probes, providing a lot of valuable host information.

   Execute the aggressive detection using the following command:
    ```bash
    $ sudo nmap -A 10.0.2.4
    ```

    ![HTTP Service](/images/http.png)
    ![Target information](/images/host_infos.png)

   From the obtained results, we discovered that:
    * The OS installed on the target machine is **Linux 2.6**.
    * The kernel version is **`linux_kernel:2.6`**.
    * The hostname is **`metasploitable`**.
    * There is an **HTTP service** running on port 80, which is **`Apache/2.2.8 (Ubuntu) DAV/2`**.



2. After identifying the running web service on port 80, the next step is to access the service via a web browser to confirm the existence and nature of the web applications hosted on the target system.
   
   From the **Attacker Machine (Kali Linux)**, open the **Firefox** web browser.
   In the address bar, connect to the target system on port 80 by entering the following URL (using the identified target IP address):
       ```
       http://10.0.2.4
       ```
   ![HTTP Service](/images/web_service.png)
   
   You will notice the existence of several intentionally vulnerable web applications. We will focus specifically on **DVWA** (Damn Vulnerable Web Application), a PHP/MySQL application designed for educational purposes.
   Navigate to the DVWA login page:
       ```
       [http://10.0.2.5/dvwa/login.php](http://10.0.2.4/dvwa/login.php)
       ```
   
   

3. To systematically discover common security issues and potential vulnerabilities in the web application, we will employ the automated web vulnerability scanner, **Nikto** to scan the DVWA application and identify common misconfigurations, potentially dangerous files, and known vulnerabilities.


   Execute the `nikto` command from the Kali Linux terminal, specifying the target URL:
   
   ```bash
   $ nikto -h [http://10.0.2.5/dvwa](http://10.0.2.5/dvwa)
   ```
   ![HTTP Service](/images/nikto_scan.png)

   The scan reveal the existence of an accessible modification history file, such as CHANGELOG.txt.
   
5. From the **Attacker Machine (Kali Linux)**, open the Firefox browser and navigate directly to the file using the following URL:
    ```
    [http://10.0.2.5/dvwa/CHANGELOG.txt](http://10.0.2.5/dvwa/CHANGELOG.txt)
    ```
    ![HTTP Service](/images/changelog.png)
    A quick review of the file's content reveals development notes and modification history.This discovery is highly valuable, as the attacker now has a confirmed **valid username (`admin`)** for the target application, which simplifies the subsequent task of cracking or bypassing the authentication mechanism.






