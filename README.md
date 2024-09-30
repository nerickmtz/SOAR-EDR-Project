# SOAR EDR Project

## Objectives

The main objective of this SOAR EDR playbook is to automate threat detection, notification, and response using the following components:

1. **LimaCharlie:**  
   - Detect security threats such as HackTools.
   - Trigger events based on threat detection and send them to Tines.

2. **Tines:**  
   - Orchestrate the detection and response flow by receiving the events from LimaCharlie.
   - Notify relevant stakeholders via Slack and Email with the following details:
     - Time
     - Computer Name
     - Source IP
     - Process
     - Command Line
     - File Path
     - Sensor ID
     - Link to the Detection (if applicable)
   - Prompt the user with the option to isolate the machine.
     - If **Yes**: LimaCharlie will automatically isolate the machine, and a message confirming isolation will be sent to Slack.
     - If **No**: A message will be sent to Slack, asking for further investigation.

3. **Slack & Email Notifications:**  
   - Slack and Email will be used to communicate key details of the threat detection and the machine isolation status.

This playbook aims to streamline incident response by integrating automatic detection with user-driven decision-making, ensuring that potential threats are handled quickly and efficiently.

![SOAR EDR 1](https://github.com/user-attachments/assets/8e1dcab5-ac87-47ae-a86a-d1c86058e128)

## Setup

### Step 1: Creating and Linking a Windows Machine in LimaCharlie

To begin, a virtual machine running Windows was created using VirtualBox. This machine was then linked to **LimaCharlie** using the provided installation keys.

1. **Create a Virtual Machine in VirtualBox**
   - Launch VirtualBox and create a new Windows machine by following the usual setup instructions for VirtualBox.
   - Install and configure the operating system as needed.

2. **Install the LimaCharlie Agent**
   - Once the Windows machine is up and running, download and install the **LimaCharlie Agent**.
   - Use the installation keys provided by LimaCharlie to link the machine to the platform.

3. **Verify Installation**
   - After installation, check the status of the **LimaCharlie Agent** by viewing the **Services** on the Windows machine.
   - You should see **LimaCharlie** running with the status **Running** and the startup type set to **Automatic**.

Here’s a screenshot showing the successful installation and status of the LimaCharlie agent:

![2](https://github.com/user-attachments/assets/d7e6cd5f-7360-4bef-91bd-dd90d4448ae3)

### Step 2: Verifying the Windows Machine in LimaCharlie

Once the LimaCharlie agent is successfully installed on the Windows machine, you can verify that the machine is running and properly linked in the LimaCharlie dashboard.

1. **Navigate to LimaCharlie Dashboard**
   - Open the LimaCharlie web interface and navigate to the **Sensors** section.
   - Here, you should see your linked Windows machine listed, along with its details such as:
     - **Hostname**
     - **Network Access**
     - **External IP**
     - **Sensor ID**
     - **Installer ID**

2. **Isolate from Network (Optional)**
   - You have the option to isolate the machine from the network if required by the playbook.

3. **Sensor Details**
   - The dashboard will also display the sensor’s **Last Time Alive**, which indicates the last time the machine communicated with LimaCharlie.
   - The **Sensor Status** should be active (green checkmark) to confirm that the sensor is properly working.

Here’s a screenshot showing the machine running in LimaCharlie:

![3](https://github.com/user-attachments/assets/c7120a3d-a510-4559-a361-256a7e39ad38)

### Step 3: Detecting Malicious Activity (LaZagne.exe) in LimaCharlie

To test the detection capabilities of the LimaCharlie agent, a well-known malware tool called **LaZagne.exe** was downloaded and executed on the Windows machine.

1. **Download and Execute LaZagne.exe**
   - The **LaZagne** tool, which is used for extracting passwords, was downloaded to the Windows machine.
   - Once executed, the LimaCharlie agent monitored the activity and sent detailed detection logs to the LimaCharlie dashboard.

2. **Detection in LimaCharlie**
   - LimaCharlie successfully detected the execution of **LaZagne.exe** and generated a detailed event report.
   - The report contains important details such as:
     - **Command Line:** Path to the executed file.
     - **File Path:** Location of the file on the machine.
     - **Process ID** and **Parent Process ID.**
     - **Memory Usage** and **Thread Count.**
     - **Timestamp** of the event.
     - **User Information:** The user that executed the file.
   - This information helps in investigating and responding to potential threats in real-time.

Here’s a screenshot of the detection log in LimaCharlie:

![4](https://github.com/user-attachments/assets/45f644e5-9b72-4093-bf6d-fd90adc0f444)

### Step 4: Creating a Custom Detection Rule for LaZagne.exe

To further enhance the detection capabilities of the LimaCharlie agent, I created a custom detection rule that specifically targets the execution of **LaZagne.exe**. This rule was based on pre-existing detection templates and edited to suit this particular case.

#### Custom Detection Rule

The detection rule is structured to identify specific characteristics of the LaZagne malware, such as:

- **File Path:** The rule looks for processes that match the `LaZagne.exe` file path.
- **Command Line:** It also monitors the command line for instances of the name `LaZagne`.
- **File Hash:** The rule verifies the hash of the file to ensure it matches known malicious variants of LaZagne.

Here’s the custom detection rule I created:

```yaml
events:
  - NEW_PROCESS
  - EXISTING_PROCESS
op: and
rules:
  - op: is windows
  - op: or
    rules:
      - case sensitive: false
        op: ends with
        path: event/FILE_PATH
        value: LaZagne.exe
      - case sensitive: false
        op: contains
        path: event/COMMAND_LINE
        value: LaZagne
      - op: is
        path: event/HASH
        value: '467e49f1f795c1b08245ae621c59cdf06df630fc1631dc8059da9a032858a486'
```
![5](https://github.com/user-attachments/assets/73b82f3a-c9cb-4ca1-8986-43a44d87bcbf)
![6](https://github.com/user-attachments/assets/a65e3a3d-aa8a-45da-901b-53446940c2af)

### Step 5: Verifying the Detection of LaZagne.exe

To confirm that the detection rule is working as expected, I re-executed **LaZagne.exe** on the Windows machine. The custom detection rule triggered successfully, and the following details were captured in the LimaCharlie detection log:

#### Detection Output

The detection output provided detailed information about the event, including:

- **Command Line:** The path and name of the executed file.
- **File Path:** The location of the file.
- **File Hash:** The unique hash of the LaZagne.exe file.
- **Memory Usage:** Memory consumed by the process and its parent process.
- **Process ID and Parent Process ID:** Identifiers for the LaZagne.exe process and its parent process.
- **User Information:** The user who executed the file.
- **Event Type:** NEW_PROCESS was detected, indicating a new process was started.

Here’s a screenshot of the detection output:

![10](https://github.com/user-attachments/assets/a984291d-1998-47b7-97f4-36746ebcec0d)

This confirms that the custom detection rule is working as expected and can accurately identify instances of **LaZagne.exe** execution on the monitored machine.

### Step 6: Using Tines to Create a Webhook for Event Detection

To automate the detection and response process further, a **Webhook** was created in **Tines** to retrieve detection events from LimaCharlie. The webhook is configured to listen for specific detection events, such as those triggered by the execution of **LaZagne.exe**.

#### Webhook Setup in Tines

1. **Create Webhook in Tines:**
   - A new Webhook was created in **Tines** with the purpose of retrieving detection events from LimaCharlie.
   - The Webhook listens for specific triggers related to the detection of **LaZagne.exe**, as defined by the custom detection rule.

2. **Webhook Output:**
   - The Webhook captures detailed event information, including:
     - **Command Line:** The exact command used to execute LaZagne.
     - **File Path:** The location of the executable file.
     - **File Hash:** A unique hash of the executable for verification.
     - **Process ID and Parent Process ID.**
     - **User Information:** The user responsible for the execution.

3. **Event Retrieval:**
   - The webhook successfully retrieves and logs the detection events triggered by LimaCharlie. This automation allows for quicker response and investigation of potential threats by providing real-time data.

Here’s a screenshot showing the webhook and its output:

![11](https://github.com/user-attachments/assets/05f12b54-62e6-4468-baac-e08b8dc7eb0b)

This webhook is a crucial part of automating the workflow by allowing events to be retrieved and processed automatically whenever a detection, such as **LaZagne.exe**, is triggered.

### Step 7: Sending Alerts via Slack and Email Using Tines

In this step, I extended the automation workflow by adding new actions in **Tines** to send detection alerts to both **Slack** and **Email**. This ensures that critical detection events are communicated to the relevant teams in real-time.

#### Slack Notification

1. **Configuring Slack Alerts:**
   - A new story was added in **Tines** to automatically send a message to a specific Slack channel whenever a detection, such as **LaZagne.exe**, is triggered.
   - The Slack message contains key details, including:
     - Title: The detection name.
     - Time: The timestamp of the detection.
     - Computer: The affected machine.
     - Source IP: The IP address of the machine.
     - Username: The user who executed the file.
     - File Path and Command Line: Information about the detected executable.
     - Sensor ID: Unique identifier for the sensor.
     - Detection Link: A link to view the detection in LimaCharlie for further investigation.

Here’s an example of the Slack alert:

![14](https://github.com/user-attachments/assets/81fba27d-8b68-4e22-b51a-37c913113674)

#### Email Notification

2. **Configuring Email Alerts:**
   - Similarly, an email alert was configured in **Tines** to send a notification to a predefined email address with the same detection details.
   - The email contains all the relevant event details, similar to the Slack message, and includes a direct link to the detection in LimaCharlie for review.

Here’s an example of the email alert:

![16](https://github.com/user-attachments/assets/e195e54d-df0c-4c3f-9b12-fbebcb86b0b4)

This step ensures that real-time alerts are sent to both Slack and Email, enabling prompt responses to detected threats like **LaZagne.exe**.

### Step 8: Creating a User Prompt in Tines

To further improve the response workflow, I configured a **User Prompt** in **Tines**. This prompt allows security personnel to decide whether to isolate the machine when a detection event occurs. Based on the response, the system will either proceed to isolate the machine or alert the team to investigate.

#### User Prompt Configuration

1. **Slack Notification for Unisolated Machines:**
   - If the machine was not isolated after detection, a notification is automatically sent to the relevant Slack channel asking the team to investigate the incident.
   
Here’s an example of the Slack notification:

![17](https://github.com/user-attachments/assets/d43625b9-1b84-4d49-92a6-766bf5ad6767)

2. **User Prompt for Isolation:**
   - When a detection, such as **LaZagne.exe**, is triggered, a user prompt is generated that asks if the machine should be isolated.
   - The prompt includes all key details of the detection:
     - Title: The detection name.
     - Time: The timestamp of the detection.
     - Computer: The affected machine.
     - Source IP: The IP address of the machine.
     - Username: The user who executed the file.
     - File Path and Command Line: Information about the detected executable.
     - Sensor ID and Detection Link.

   The user can choose between **Yes** or **No** to either isolate the machine or leave it unisolated.

Here’s an example of the user prompt:

![18](https://github.com/user-attachments/assets/b8c1bcc7-3e86-4f36-b1f2-a3a232993f4c)

#### User Response

- If the user selects **Yes**, LimaCharlie will automatically isolate the machine, and a confirmation message will be sent to Slack.
- If the user selects **No**, a message will be sent to Slack indicating that the machine was not isolated and requires further investigation.

This step allows for human decision-making in the workflow, ensuring that machines are only isolated when necessary.

### Step 9: Machine Isolation Using HTTP Request in Tines

To enable automatic machine isolation after a detection event, I leveraged a pre-built HTTP request from **LimaCharlie** that allows isolation of the sensor (machine) through an API call. This step integrates with the user prompt to give the security team the option to isolate the machine directly from the Tines interface.

#### Full Diagram Overview

This diagram shows the full workflow, from detection to user decision-making, and finally to machine isolation or notification:

![21](https://github.com/user-attachments/assets/af88b18b-41a7-4616-ae47-c67e95724bfb)

#### Key Workflow Components:

1. **Webhook to Retrieve Detections:**
   - The workflow starts with a Webhook that retrieves detections from LimaCharlie.

2. **Slack and Email Notifications:**
   - After retrieving the detection, notifications are sent via Slack and Email to alert the relevant teams of the incident.

3. **User Prompt:**
   - A user prompt is generated, allowing security personnel to decide whether to isolate the machine. The user can choose **Yes** to isolate the machine or **No** to investigate further without isolation.

4. **HTTP Request for Isolation (Yes Path):**
   - If the user chooses to isolate the machine, an HTTP request is made to **LimaCharlie**'s API to isolate the sensor (machine).
   - Another HTTP request checks the isolation status to confirm that the machine has been successfully isolated.

5. **HTTP Request (No Path):**
   - If the user chooses **No**, a Slack message is sent informing the team that the machine was not isolated and needs further investigation.

6. **Final Slack Notifications:**
   - Whether the machine is isolated or not, final messages are sent to Slack to notify the team of the action taken.

#### Integration with the Original Playbook

This workflow corresponds to the original playbook design:
- **Detection** is performed by LimaCharlie, and Tines orchestrates the response.
- **Notifications** are sent via Slack and Email.
- **User Decision**: The team is prompted to decide if the machine should be isolated.
- **Machine Isolation**: If approved, the machine is isolated through an HTTP request to the LimaCharlie API.

This automation significantly streamlines the response to security incidents, allowing for real-time isolation of compromised machines.

### Step 10: Machine Isolation Demonstration (Video)

To demonstrate the full workflow in action, here is a video showing how the system automatically isolates a machine when a detection event is triggered, and the user selects "Yes" in the isolation prompt. The video walks through the process from detection to notification and finally to machine isolation through the pre-built HTTP request in Tines.

You can watch the video below:

https://github.com/user-attachments/assets/58be7978-0eb1-4aa9-8e7c-6e119d9b26f7

#### Video Highlights:
1. **Detection Triggered**: A detection event is generated for **LaZagne.exe**.
2. **User Prompt**: The user receives a prompt asking whether to isolate the machine.
3. **User Selects "Yes"**: The user chooses to isolate the machine.
4. **HTTP Request Sent**: An HTTP request is automatically sent to **LimaCharlie** to isolate the machine.
5. **Confirmation**: A Slack message confirms that the machine has been successfully isolated.

This video showcases the seamless integration of LimaCharlie, Tines, Slack, and email notifications to handle real-time incident response.

### Skills Learned

Throughout the course of this project, several key skills and competencies were developed and honed, including:

1. **Integration of SOAR Tools:**
   - Successfully integrated multiple SOAR (Security Orchestration, Automation, and Response) tools like **LimaCharlie**, **Tines**, **Slack**, and **Email** into a seamless incident response workflow.
   
2. **Custom Detection Rules:**
   - Gained experience in creating and testing **custom detection rules** in **LimaCharlie**, specifically targeting well-known malware (e.g., LaZagne.exe) using file path, command line, and hash-based detections.

3. **Automation with Tines:**
   - Mastered the use of **Tines** to automate detection, alerting, and decision-making processes through:
     - Webhooks for retrieving detection events.
     - Automated email and Slack notifications for real-time incident alerts.
     - User prompts for decision-making (e.g., machine isolation).

4. **HTTP API Requests:**
   - Utilized **HTTP API requests** to automate machine isolation in **LimaCharlie**, allowing for hands-off execution of key remediation actions based on user inputs in Tines.

5. **Incident Response Orchestration:**
   - Developed skills in orchestrating a complete incident response workflow from detection to remediation, ensuring that incidents are handled efficiently with minimal manual intervention.

6. **Slack and Email Notifications:**
   - Configured **Slack** and **Email** integrations to deliver alerts and updates, enabling communication across security teams in real time.

7. **Security Best Practices:**
   - Practiced and applied security best practices in detecting, analyzing, and mitigating threats, all within an automated and structured response framework.

---

### Conclusion

This project successfully demonstrated the power and flexibility of a SOAR-driven incident response workflow, using **LimaCharlie**, **Tines**, **Slack**, and **Email** to automate detection, notification, and response to security incidents. By integrating these tools, we built a highly effective system capable of detecting threats (e.g., **LaZagne.exe**), alerting the appropriate teams, and enabling prompt, automated remediation through user-driven decisions.

The project has illustrated the potential for further scalability and customization in real-world environments, where rapid response times and automated workflows can greatly reduce the impact of security incidents. Additionally, the skills gained throughout the project provide a strong foundation for future work in security automation, incident response, and threat detection.

Moving forward, this workflow can be adapted to other types of threats, and additional actions can be integrated to improve overall security posture. This project is an excellent example of how security automation tools can transform traditional incident response processes into a proactive, efficient, and scalable operation.















