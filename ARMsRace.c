import socket
from functools import reduce
import urllib.parse as urlparse
from requests.exceptions import ConnectionError
from arm_disassemble import disas_arm,display_ins,display_res

def parse_req(data)->str:
    start_text=": "
    start_index = data.find(start_text)
    data = data[start_index + len(start_text):]
    data.replace(" ","")
    data.replace("\n","")
    data.rstrip()
    return data


def recieve_until_char(s,recv_char):
    data=b''
    while True:
        buffer=s.recv(1)
        if not buffer:
            break
        else:
            data+=buffer
            if recv_char in data:
                break
    return data

def _get_imd(op_str):
    hex_index=op_str.find("#")
    hex_val=op_str[hex_index:]
    hex_val=hex_val.replace("#","")
    hex_val=hex_val.replace("0x","")
    # print("hex val : ",hex_val)
    imd=int(hex_val,16)
    return imd


def get_reg_and_imd(op_str):
    reg_index=_reg_index(op_str)
    imd=_get_imd(op_str)
    return reg_index,imd

def _reg_index(op_str):
    reg_index=None
    if "r0" in op_str:
        reg_index=0
    elif "r1" in op_str:
        reg_index=1
    elif "r2" in op_str:
        reg_index=2
    return reg_index

def get_op_dest(op_str):
     op_list=op_str.split(",")
     dest=_reg_index(op_list[0])
     op1=_reg_index(op_list[1])
     if len(op_list)==3:
        op2=_reg_index(op_list[2])
     else:
        op2=None
     return dest,op1,op2

def _check_req_op(dest,op1,op2,op_str):
    if not op2:
        op2=_get_imd(op_str)
    return [0,0,0]==[dest,op1,op2] or [0,0,1]==[dest,op1,op2]
     

def calc_ins_res(registers,dis_ins):
    dis_res=display_ins(dis_ins)
    # print(">> ",dis_res)
    mnemonic=dis_ins["mnemonic"] 
    op_str=dis_ins["op_str"]

    if mnemonic=="movt":
            reg_index,imd=get_reg_and_imd(op_str)
            # print(f"Reg index : {reg_index} , imd : {imd}")
            upper_bits = imd << 16
            registers[reg_index]+=upper_bits

    elif mnemonic in ["mov","movw"]:
            reg_index,imd=get_reg_and_imd(op_str)
            # print(f"Reg index : {reg_index} , imd : {imd}")
            registers[reg_index]=imd

    dest,op1,op2=get_op_dest(op_str)
    # print(f"Dest : {dest}, OP1 : {op1} , OP2 : {op2}")
    if _check_req_op(dest,op1,op2,op_str):
        if mnemonic =="add":
            registers[0]+=registers[1]+registers[2]
            #  registers[dest]=registers[op1]+registers[op2]
        
        elif mnemonic =="sub":
            # add 0xFFFFFFFF for converting -ve to unsigned int
            registers[0]=(registers[0]-registers[1]-registers[2])+0xFFFFFFFF
            #  registers[dest]=registers[op1]-registers[op2]

        elif mnemonic == "rsb":
            #  dest,op1,op2=get_op_dest(op_str)
            #  if op2 :
            #     print(f"Dest : {dest}, OP1 : {op1} , OP2 : {op2}")
            #     registers[dest]=registers[op2]-registers[op1]
            #  else:
            #     op2=_get_imd(op_str)
            #     print(f"Dest : {dest}, OP1 : {op1} , OP2 : {op2}")
            #     registers[dest]=op2-registers[op1]

            # 2^32-r0
            registers[0]=0x100000000-registers[0]

        
        elif mnemonic == "and":
            #  registers[dest]=registers[op1]&registers[op2]
            registers[0]&=registers[1]&registers[2]

        elif mnemonic == "eor":
            #  registers[dest]=registers[op1]^registers[op2]
            registers[0]^=registers[1]^registers[2]
            
        elif mnemonic == "mul":
            #  registers[dest]=registers[op1]*registers[op2]
            registers[0]*=registers[1]*registers[2]


        elif mnemonic == "orr":
            #  registers[dest]=registers[op1]|registers[op2]
            registers[0]|=registers[1]|registers[2]
        # else :
            #  print("Mnemonic not detected : ",mnemonic)
    return registers

def calc_soln(arm_code)->str:
    registers=[0,0,0]
    arm_dis=disas_arm(arm_code)
    registers=reduce(calc_ins_res,arm_dis,registers)
    return  hex(registers[0]&0xFFFFFFFF)


def _log_lvl(arm_bin,disas,payload,lvl):
    res=arm_bin+"\n"+"="*100+"\n"+disas+"\n"+"*="*50+"\n"+payload
    with open(f"logs/lvl_{lvl}.txt",'w') as file:
        file.write(res)

def log_data(data,lvl,payload):
    arm_code=parse_req(datadecode())
    disas_res=disas_arm(arm_code)
    disas_res=display_res(disas_res)
    _log_lvl(arm_code,disas_res,payload,lvl)

def main():
    HOST="83.136.254.223"
    PORT=38861
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((HOST,PORT))
    for i in range(51):
        data=recieve_until_char(s,b'\n').decode()
        print(data)
        print("="*100)
        arm_code=parse_req(data)
        payload=calc_soln(arm_code)+"\n"
        response = recieve_until_char(s, b'Register r0:')
        print("Sending payload : ",payload)
        s.send(payload.encode())
        log_data(data,i+1,payload)


if __name__=="__main__":
    main()
