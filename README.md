# Radiotap

Il nostro radiotap è costruito così:

### Header

* **Version** &rarr; `0x00` _(1 byte)_
* **Padding** &rarr; `0x00` _(1 byte)_
* **Len** &rarr; `0x0015` _(2 byte) (little endian)_
* **Fields** &rarr; `0x20088c0e` _(4 byte) (little endian)_

### Body

* **Flags** &rarr; `0x10` _(1 byte)_
    * `0x10` frame includes FCS
* **Rate** &rarr; `0x82` _(misurato in 500 Kbps) (1 byte)_
* **Channel**:
    * Frequenza &rarr; `da decidere` _(misurato in MHz) (2 byte) (Little Endian)_
    * Flags &rarr; `0x00c0` _(2 byte) (little endian)_
        * `0x0040` OFDM channel
        * `0x0080` 2 GHz spectrum channel
* **dBm TX power** &rarr; `0x14` _(misurato in dBm) (max 30 dBm) (1 byte)_
* **Antenna** &rarr; `0x01` _(indice antenna) (1 byte)_
* **TX flags** &rarr; `0x0038` _(2 byte) (little endian)_
    * `0x0008` Transmission shall not expect an ACK frame and not retry when no ACK is received
    * `0x0010` Transmission includes a pre-configured sequence number that should not be changed by the driver’s TX
      handlers
    * `0x0020` Transmission should not be reordered relative to other frames that have this flag set
* **MCS**: _(3 byte)_
    * **Know** &rarr; `0x7f` _(1 byte)_
        * `0x01` bandwidth
        * `0x02` MCS index known
        * `0x04` guard interval
        * `0x08` HT format
        * `0x10` FEC type
        * `0x20` STBC known
        * `0x40` Ness known (Number of extension spatial streams)
        * `0x00` Ness data - bit 1 (MSB) of Number of extension spatial streams
    * **Flags** &rarr; `0x31` _(1 byte)_
        * `0x01` bandwidth:
            * `0x00` &rarr; 20
            * `0x01` &rarr; 40
            * `0x10` &rarr; 20L
            * `0x11` &rarr; 20U
        * `0x00` guard interval:
            * `0x00` &rarr; long GI
            * `0x04` &rarr; short GI
        * `0x00` HT format
            * `0x00` &rarr; mixed,
            * `0x08` &rarr; greenfield
        * `0x10` FEC type
            * `0x00` &rarr; BCC
            * `0x10` &rarr; LDPC
        * `0x20` Number of STBC streams:
            * `0x00` &rarr; 0,
            * `0x20` &rarr; 1,
            * `0x40` &rarr; 2,
            * `0x60` &rarr; 3
        * `0x00` Ness - bit 0 (LSB) of Number of extension spatial streams
    * **MCS index** &rarr; `0x07` _(1 byte)_