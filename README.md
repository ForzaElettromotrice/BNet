# Istruzioni per l'uso

1. Inizializare la libreria con `initPcap()`
2. `Opzionale` Settare la callback function con `setCallback()`
3. Creare l'handle con `createHandle()`
3. Attivare l'handle con `activateHandle()`
4. Iniziare l'ascolto con `loopPcap()`
5. Chiudere il loop con `stopPcap()`

Durante il loop, per inviare un pacchetto usare `addPacket()`