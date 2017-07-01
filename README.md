# fleutan
(Altger. fliessen, fliessend, engl. flowing)

![Alt text](logo.png?raw=true "fleutan")

# Purpose

Fleutan aims at forming an complementing or functionality enriching agglomeration of tools or mechanisms all around flowing on unixoid systems to enhance the way engineers can research, analyze and operate their nodes. It's thereby focused on the single endpoint and tries to reach or look into the network fabrics as deeply as it can when it comes to what is available to it on the certain systems acting as the endpoint.

# Target Audience

- all kinds of systems engineers, foremost operations focused
- network researchers

# Examples

To show the prevailing association of flows to cpus rin

```
$ python fleutan.py flows --cpu -i 5
~>/usr/lib/thunderbird/thunderbird(2847)
tcp              192.168.10.50#34718                     212.227.17.170#993
tcp              192.168.10.50#55258                     194.25.134.115#993
___

####################################################################################################
*************************************************************************          100.00          0
                                                                                     0.00          1
                                                                                     0.00          2
                                                                                     0.00          3
                                                                                     0.00          4
                                                                                     0.00          5
                                                                                     0.00          6
                                                                                     0.00          7
...
~>hexchat(11290)
tcp       2003:62:4655:968b:18d0:33a6:3314:7c7#34482               2001:5a0:3604:1:64:86:243:181#6667
tcp       2003:62:4655:968b:18d0:33a6:3314:7c7#38930               2a02:2f0d:bff0:1:81:18:73:123#6667
tcp       2003:62:4655:968b:18d0:33a6:3314:7c7#35660                 2605:ac00:0:39::38#6697
___

####################################################################################################
                                                                                     0.00          0
                                                                                     0.00          1
                                                                                     0.00          2
                                                                                     0.00          3
*************************************************************************          150.00          4
                                                                                     0.00          5
                                                                                     0.00          6
                                                                                     0.00          7
...
~>/usr/lib/firefox/firefox(11181)
tcp       2003:62:4655:968b:18d0:33a6:3314:7c7#59780                2a00:1450:4021:c::b#443
tcp       2003:62:4655:968b:18d0:33a6:3314:7c7#59774                2a00:1450:4021:c::b#443
tcp       2003:62:4655:968b:18d0:33a6:3314:7c7#44950               2a00:1450:4001:81f::200e#443
___

####################################################################################################
************************                                                            15.00          0
**************                                                                       9.00          1
***************************************                                             24.00          2
*****************************                                                       18.00          3
****                                                                                 3.00          4
                                                                                     0.00          5
**************************************************************************          45.00          6
***********************************************************                         36.00          7
```
Helpful is also to see the paths certain flows are traversing:

```
$ python fleutan.py paths -d
**>Flows
tcp       2003:62:4655:968b:18d0:33a6:3314:7c7#36582                 2605:ac00:0:39::38#6697        p0
tcp       2003:62:4655:968b:18d0:33a6:3314:7c7#41570               2600:3c02::f03c:91ff:fe59:7d2e#6667        p1
tcp              192.168.10.50#35238                     212.227.17.170#993        p2
tcp       2003:62:4655:968b:18d0:33a6:3314:7c7#41436               2001:708:40:2001::f5ee:d0de#6667        p3

..>paths

p0                                                                     p1                                                                     p2             
---------------------------------------------------------------------  ---------------------------------------------------------------------  -------------  
2003:0:1801:c209::1                                                    2003:0:1801:c209::1                                                    speedport.ip   
['2003:0:1801:c258::2', '2003:0:1803:8358::2', '2003:0:1801:c258::2']  ['2003:0:1801:c258::2', '2003:0:1803:8358::2', '2003:0:1801:c258::2']  87.186.224.45  
2003:0:130c:8000::1                                                    ['2600:3c02:4444:3::2', '2600:3c02:4444:4::2']                         217.0.74.226   
2003:0:130c:8024::2                                                    moon.freenode.net                                                      217.239.52.94  
2001:5a0:0:501::16                                                                                                                            80.157.204.86  
2001:1978:2:5::d                                                                                                                              imap.gmx.net                                                   
2001:1978:203::e                                                                                                                                                                                             
2001:1978:1300:10::12                                                                                                                                                                                        
2605:ac00:ffff:ffff:ffff:ffff:ffff:fffe                                                                                                                                                                      
2605:ac$ python fleutan.py paths -d
**>Flows
tcp       2003:62:4655:968b:18d0:33a6:3314:7c7#36582                 2605:ac00:0:39::38#6697        p0
tcp       2003:62:4655:968b:18d0:33a6:3314:7c7#41570               2600:3c02::f03c:91ff:fe59:7d2e#6667        p1
tcp              192.168.10.50#35238                     212.227.17.170#993        p2
tcp       2003:62:4655:968b:18d0:33a6:3314:7c7#41436               2001:708:40:2001::f5ee:d0de#6667        p3

..>paths

p0                                                                     p1                                                                     p2             
---------------------------------------------------------------------  ---------------------------------------------------------------------  -------------  
2003:0:1801:c209::1                                                    2003:0:1801:c209::1                                                    speedport.ip   
['2003:0:1801:c258::2', '2003:0:1803:8358::2', '2003:0:1801:c258::2']  ['2003:0:1801:c258::2', '2003:0:1803:8358::2', '2003:0:1801:c258::2']  87.186.224.45  
2003:0:130c:8000::1                                                    ['2600:3c02:4444:3::2', '2600:3c02:4444:4::2']                         217.0.74.226   
2003:0:130c:8024::2                                                    moon.freenode.net                                                      217.239.52.94  
2001:5a0:0:501::16                                                                                                                            80.157.204.86  
2001:1978:2:5::d                                                                                                                              imap.gmx.net                                                   
2001:1978:203::e                                                                                                                                                                                             
2001:1978:1300:10::12                                                                                                                                                                                        
2605:ac00:ffff:ffff:ffff:ffff:ffff:fffe                                                                                                                                                                      
2605:ac00:0:39::38                       00:0:39::38     
```
