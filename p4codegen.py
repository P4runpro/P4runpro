import jinja2
import json
import argparse

# Path information.
TEMPLATE_PATH = 'template/'
P4_PATH = 'p4src/'
#CONFIG_PATH = './'

if __name__ == "__main__":
    '''
    # Extract configs
    with open(CONFIG_PATH + 'config.json', 'r') as fr:
        CONF = json.load(fr)

    CONF["parsing_len"] = len(CONF["parsing_logic"])
    '''

    CONF = [["Ingress", "Egress"], [[1, 11], [0, 12]], [0, 11],  #RPB stage configurations for ingress and egress pipeline
            [[[],                                                      #CRC16 polinomial for each RPB
             ['0x18005', 'true', 'false', 'true', '0x0000', '0x0000'], #CRC16
             ['0x18005', 'false', 'false', 'true', '0x0000', '0x0000'], #CRC16 buypass
             ['0x18005', 'false', 'false', 'true', '0x800D', '0x0000'], #CRC16 dds 110
             ['0x10589', 'false', 'false', 'true', '0x0001', '0x0001'], #CRC16 dect
             ['0x13D65', 'true', 'false', 'true', '0xFFFF', '0xFFFF'], #CRC16 dnp
             ['0x13D65', 'false', 'false', 'true', '0xFFFF', '0xFFFF'], #CRC16 en 13757
             ['0x11021', 'false', 'false', 'true', '0x0000', '0xFFFF'], #CRC16 genibus
             ['0x18005', 'true', 'false', 'true', '0xFFFF', '0xFFFF'], #CRC16 maxim
             ['0x11021', 'true', 'false', 'true', '0xFFFF', '0x0000'], #CRC16 mrcf4xx
             ['0x11021', 'true', 'false', 'true', '0x554D', '0x0000']], #CRC16 riello
            [['0x18BB7', 'false', 'false', 'true', '0x0000', '0x0000'], #CRC16 t10 dif
             ['0x1A097', 'false', 'false', 'true', '0x0000', '0xFFFF'], #CRC16 teledisk
             ['0x18005', 'true', 'false', 'true', '0x0000', '0xFFFF'], #CRC16 usb
             ['0x11021', 'true', 'false', 'true', '0x0000', '0xFFFF'], #x25
             ['0x11021', 'false', 'false', 'true', '0x0000', '0x0000'], #xmodem
             ['0x18005', 'true', 'false', 'true', '0xFFFF', '0x0000'], #modbus
             ['0x11021', 'true', 'false', 'true', '0x0000', '0x0000'], #kermit
             ['0x11021', 'false', 'false', 'true', '0xFFFF', '0x0000'], #CRC ccitt false
             ['0x11021', 'false', 'false', 'true', '0x1D0F', '0x0000'], #CRC aug ccitt
             ['0x1C867', 'false', 'false', 'true', '0xFFFF', '0x0000'], #CRC16 CDMA2000
             ['0x11021', 'true', 'false', 'true', '0x89EC', '0x0000'], #CRC16 TMS37157
             ['0x11021', 'true', 'false', 'true', '0xC6C6', '0x0000']]] #CRC A
            ]
    
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_PATH),  trim_blocks=True, lstrip_blocks=True)  
    # Generate p4r2.p4 and metadata.p4
    template = env.get_template('runproblock.p4template')
    template_out = template.render(CONF = CONF)
    with open(TEMPLATE_PATH + 'generated_runproblock.p4', 'w') as fw:
        fw.writelines(template_out)
        fw.close()


