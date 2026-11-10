//Scan event viewer logs
#include "./extended.h"
#include <iostream>

/*
1002 Audit log was cleared
1120 Defender remediation failed
4698 SchTask was created
4699 SchTask was deleted
4702 SchTask was updated
4783 Pwd hash accessed
5025 WinFirewall stopped
7034 Service termination 
7045 Service instalation
*/
void forensicFind() {
	return;
}

/*
XXXX idk
*/
void sysmonCheck() {
	// if sysmon, check it. Else return
	return;

}

void eventView() {
	forensicFind();
	sysmonCheck();
}