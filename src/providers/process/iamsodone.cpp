// Process injection
// Process hollowing
// Process ghosting
// Process doppelgänging
// Process herpaderping
/*
 You would need to consume events from at least two key providers:

Microsoft-Windows-Kernel-Process: For process creation events.
Microsoft-Windows-Kernel-File: For file operation events.
Look for the Malicious Sequence: The detection logic involves correlating events in a specific order, all originating from the same parent process:

Event 1 (File Create): A Microsoft-Windows-Kernel-File event shows a file being created (e.g., C:\Users\Admin\AppData\Local\Temp\tmpXXXX.tmp).
Event 2 (Set Deletion): A Microsoft-Windows-Kernel-File event with SetInfo operation for FileDispositionInformation is logged for that same file. This is the "delete-on-close" flag being set.
Event 3 (Process Create): A Microsoft-Windows-Kernel-Process event (Event ID 1: Process Start) is logged. The ImageFileName in this event will point to the temporary file from Event 1.
Event 4 (File Close): A Microsoft-Windows-Kernel-File Cleanup and Close event occurs, which triggers the file's deletion from the disk.
The "Smoking Gun": A monitoring tool would see this rapid sequence and could immediately verify it. If it tries to access the ImageFileName from the process creation event moments after it's logged, the file will not exist. This combination—a process starting from a file that immediately vanishes—is a very strong indicator of Process Ghosting or a similar file-based evasion technique.
*/
// bro what is this nonsense