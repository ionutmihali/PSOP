# PSOP
### Proiect Proiectarea Sistemelor de Operare  
  
Tema proiectului: **Aplicație de tip Port Scanner**   
  
Echipa:  
*Sd. Sg. Grigore Maria Emilia*  
*Sd. Sg. Mihali Sorin Ionuț*  
  
Grupa: C113C

În acest branch vor fi postate fișiere conținând codul aferent proiectului, cât și variantele acestora.  
Pentru fiecare varianta a proiectului se va regasi un folder cu numele aferent (Exemplu: Varianta 1-codul la prima evaluare intermediara, Varianta 2- codul la a doua evaluare initiala).  

Detalii implementare:  
Varianta 1:  
Scanare range de porturi pentru a determina porturile deschise si afisarea numarului de port respectiv.  
Translatare hostname-> adresa IP  
Parametrii (range porturi, hostname, IP) introduse din interfata, de catre utilizator, in timpul rularii programului.

Varianta 2:  
Scanarea tuturor porturilor (65535).  
Determinare porturi deschise, serviciul care ruleaza pe port, cat si tipul de trafic.  
Translatare hostname-> adresa IP  
Citirea din fisier de input a unor hostname-uri/ip=uri.  
Parametrii (hostname=-h, IP=-h, timeout=timp maxim de asteptare raspuns=-t, fisier de input=-i) introduse ca argumente in momentul rularii programului, parsarea acestora cu ajutorul header-ului arg_parse.h.  
Implementare prin intermediul thread-urilor.  

Varianta 3:  
Pe langa implementarile deja facute:  
-Optiunile:  
  -output file [-o]:  scrie outputul comenzii intr-un fisier;  
  -port range [-p]: scaneaza  
    -un port (80)  
    -un range de porturi (75-85)  
  -excluded ports [-e]: in scanare, sare peste:  
    -un range de porturi (45-90)  
    -o multime de porturi (45,89,1234)  
    -un singur port: (89)  
  -threads [-T]: seteaza un alt numar de threaduri folosite in program fata de cel implicit (5)  
  -verbose [-v]: specifica si tipul de serviciu gasit pe port si tipul de protocol  
  -random [-r]: scaneaza porturile intr-o ordine aleatoare  
  -fast [-f]: nu se introduce o intarziere in scanare  
  -scanType [-s]: specificam tipul de scanare: TCP sau UDP  
  -tcp-flags [-F]: specificam flagurile din headerul TCP: [S] = tcp syn.   
-Impartirea codului din main pe functii pentru lizibilitate  
