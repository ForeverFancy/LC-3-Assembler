import re
import sys

import six

# To use the assembler: python assembler.py inputfile.asm

class Assembler(object):
    
    def __init__(self, address):
        self.address = address
        self.pseudo_ops = ['.ORIG', '.END', '.BLKW', '.FILL', '.STRINGZ']

        self.op_instructions = {"ADD": 0b0001 << 12, "AND": 0b0101 << 12, "NOT": 0b1001 << 12}

        self.ctrl_instructions = {"BRN": 0b0000100 << 9, "BRZ": 0b0000010 << 9, "BRP": 0b0000001 << 9, "BRNZ": 0b0000110 << 9,
                                  "BRZP": 0b0000011 << 9, "BRNP": 0b0000101 << 9, "BRNZP": 0b0000111 << 9,
                                  "JSR": 0b01001 << 11, "JSRR": 0b01000 << 11, "RTI": 0b1000000000000000, "JMP": 0b1100 << 12,
                                  "RET": 0b1100000111000000, "TRAP": 0b11110000 << 8, "HALT": 0b1111000000100101,
                                  "GETC": 0b1111000000100000, "OUT": 0b1111000000100001, "PUTS": 0b1111000000100010,
                                  "IN": 0b1111000000100011, "PUTSP": 0b1111000000100100,}
                                  
        self.data_movement_instructions = {"LD": 0b0010 << 12, "LDR": 0b0110 << 12, "LDI": 0b1010 << 12, "LEA": 0b1110 << 12,
                                            "ST": 0b0011 << 12, "STR": 0b0111 << 12, "STI": 0b1011 << 12}
        
        self.opcode_table = {**self.data_movement_instructions, **self.op_instructions, **self.ctrl_instructions}
        
        self.immediate_length = {'ADD': 5, 'AND': 5, 'BRN': 9, 'BRZ': 9, 'BRP': 9, 'BRNZ': 9, 'BRNP': 9, 'BRZP': 9, 'BRNZP': 9,
                                 'GETC': 0, 'HALT': 0, 'IN': 0, 'JMP': 0, 'JMPT': 0, 'JSR': 11, 'JSRR': 0, 'LD': 9, 'LDI': 9,
                                 'LDR': 6, 'LEA': 9, 'NOT': 9, 'OUT': 0, 'PUTS': 0, 'PUTSP': 0, 'RET': 0, 'RTI': 0, 'RTT': 0,
                                 'ST': 9, 'STI': 9, 'STR': 6, 'TRAP': 8, 'UNDEFINED': 0}
        self.immediate_mask = {5: 31, 9: 511, 0: 0, 11: 2047, 6: 63, 8: 255}
        self.regs = {'R%d' % i: i for i in range(0, 8)}

    def get_op_instruction(self, word, pc):
        # instruction = 0b0 << 16
        if word[0] == 'NOT':
            if len(word) > 3:
                raise SyntaxError(
                    'The number of oprands is more than excepted.\nLocation:PC='+hex(pc-1))
            try:
                DR = self.regs[word[1]] << 9
                SR1 = self.regs[word[2]] << 6
            except KeyError:
                raise KeyError(
                    'Register does not exist.\nLocation:PC='+hex(pc-1))
            return (self.op_instructions[word[0]] + DR + SR1) | (0b111111)

        elif word[0] == 'ADD' or word[0] == 'AND':
            if len(word) > 4:
                raise SyntaxError(
                    'The number of oprands is more than excepted.\nLocation:PC='+hex(pc-1))
            try:
                DR = self.regs[word[1]] << 9
                SR1 = self.regs[word[2]] << 6
            except KeyError:
                raise KeyError(
                    'Register does not exist.\nLocation:PC='+hex(pc-1))

            if word[3] in self.regs:
                SR2 = self.regs[word[3]]
                return self.op_instructions[word[0]] + DR + SR1 + SR2

            elif '#' in word[3] or 'x' in word[3] or 'X' in word[3]:
                if not self.judge_immediate(word[3], high=15, low=-17, pc=pc):
                    raise ValueError(
                        'Could not be represented as a signed number in 5 bits.\nLocation:PC='+hex(pc-1))
                try:
                    im = self.get_immediate(word[3], pc, self.immediate_mask[self.immediate_length[word[0]]])
                except BaseException:
                    raise SyntaxError('Invalid syntax.\nLocation:PC='+hex(pc-1))
                
                return self.op_instructions[word[0]] + DR + SR1 +0b100000 + im
            else:
                raise SyntaxError(
                    'Unrecognized opcode or syntax error.\nLocation:PC='+hex(pc-1))
        else:
                raise SyntaxError(
                    'Unrecognized opcode or syntax error.\nLocation:PC='+hex(pc-1))
    
    def get_data_movement_instruction(self, word, pc):
        if word[0] == 'LDR' or word[0] == 'STR':
            if len(word) > 4:
                raise SyntaxError(
                    'The number of oprands is more than excepted.\nLocation:PC='+hex(pc-1))
            try:
                DR_or_SR = self.regs[word[1]] << 9
                BaseR = self.regs[word[2]] << 6
            except KeyError:
                raise KeyError(
                    'Register does not exist.\nLocation:PC='+hex(pc-1))

            if not self.judge_immediate(word[3], high=15, low=-17, pc=pc):
                    raise ValueError(
                        'Could not be represented as a signed number in 5 bits.\nLocation:PC='+hex(pc-1))
            try:
                im = self.get_immediate(
                    word[3], pc, self.immediate_mask[self.immediate_length[word[0]]])
            except BaseException:
                raise SyntaxError('Invalid syntax.\nLocation:PC='+hex(pc-1))
            return self.data_movement_instructions[word[0]] + DR_or_SR + BaseR + im

        elif word[0] == 'LD' or word[0] == 'LDI'or word[0] == 'LEA'or word[0] == 'ST' or word[0] == 'STI':
            if len(word) > 3:
                raise SyntaxError(
                    'The number of oprands is more than excepted.\nLocation:PC='+hex(pc-1))
            try:
                DR_or_SR = self.regs[word[1]] << 9
            except KeyError:
                raise KeyError(
                    'Register does not exist.\nLocation:PC='+hex(pc-1))
            im_mask = self.immediate_mask[self.immediate_length[word[0]]]
            if word[2] in self.symbol_table:
                pc_offset = hex(int(self.symbol_table[word[2]], 16) - (pc))
                # print(pc_offset)
                if pc_offset.startswith('-'):
                    try:
                        addr = self.get_immediate(pc_offset[1:], pc, im_mask)
                    except BaseException:
                        raise SyntaxError(
                            'Invalid syntax.\nLocation:PC='+hex(pc-1))
                    pc_offset = (~int(addr) + 1) & 511
                else:
                    try:
                        pc_offset = self.get_immediate(
                            pc_offset, pc, im_mask)
                    except BaseException:
                        raise SyntaxError(
                            'Invalid syntax.\nLocation:PC='+hex(pc-1))
                return self.data_movement_instructions[word[0]] + DR_or_SR + pc_offset
            else: 
                raise SyntaxError('Symbol not found.\nLocation:PC='+hex(pc-1))
        else:
            raise SyntaxError(
                'Unrecognized opcode or syntax error.\nLocation:PC='+hex(pc-1))
                
    def get_ctrl_instruction(self, word, pc):
        if word[0] == 'RET' or word[0] == 'RTI' or word[0] == 'HALT' or word[0] == 'OUT' or word[0] == 'GETC' \
        or word[0] == 'PUTS' or word[0] == 'IN' or word[0] == 'PUTSP':
            if len(word) >= 2:
                raise SyntaxError(
                    'The number of oprands is more than excepted.\nLocation:PC='+hex(pc-1))
            return self.ctrl_instructions[word[0]]

        elif word[0] == 'JMP' or word[0] == 'JSRR':
            if len(word) > 2:
                raise SyntaxError('The number of oprands is more than excepted.\nLocation:PC='+hex(pc-1))
            try:
                BaseR = self.regs[word[1]] << 6
            except KeyError:
                raise KeyError('Register does not exist.\nLocation:PC='+hex(pc-1))
            return self.ctrl_instructions[word[0]] + BaseR

        elif 'BR' in word[0] or word[0] == 'JSR':
            if len(word) > 2:
                raise SyntaxError(
                    'The number of oprands is more than excepted.\nLocation:PC='+hex(pc-1))
            im_mask = self.immediate_mask[self.immediate_length[word[0].upper()]]
            if word[1] in self.symbol_table:
                pc_offset = hex(int(self.symbol_table[word[1]], 16) - (pc))
                if pc_offset.startswith('-'):  #TODO: A bug is to be fixed.
                    try:
                        addr = self.get_immediate(pc_offset[1:], pc, im_mask)
                    except BaseException:
                        raise SyntaxError('Invalid syntax.\nLocation:PC='+hex(pc-1))
                    if word[0] == 'JSR':   
                        pc_offset = (~int(addr) + 1) & 2047
                    else:
                        pc_offset = (~int(addr) + 1) & 511
                else:
                    try:
                        pc_offset = self.get_immediate(pc_offset, pc, im_mask)
                    except BaseException:
                        raise SyntaxError('Invalid syntax.\nLocation:PC='+hex(pc-1))
                return self.ctrl_instructions[word[0].upper()] + pc_offset
            else:
                raise SyntaxError('Symbol not found.\nLocation:PC='+hex(pc-1))
        elif 'TRAP' == word[0]:
            if len(word) > 2:
                raise SyntaxError('The number of oprands is more than excepted.\nLocation:PC='+hex(pc-1))
            if not self.judge_immediate(word[1], high=255, low=0, pc=pc):
                raise ValueError('Could not be represented as a unsigned number in 8 bits.\nLocation:PC='+hex(pc-1))
            im_mask = self.immediate_mask[self.immediate_length[word[0]]]
            try:
                vector = self.get_immediate('0' + word[1], pc, im_mask)
            except BaseException:
                raise SyntaxError('Invalid syntax.\nLocation:PC='+hex(pc-1))
            return self.ctrl_instructions[word[0]] + vector
        else:
            raise SyntaxError('Unrecognized opcode or syntax error.\nLocation:PC='+hex(pc-1))

    def judge_immediate(self, num, high, low, pc):
        if (num.startswith('0x') or num.startswith('0X')) and all(i in '-0123456789abcdefABCDEF' for i in num[2:]) and '-' not in num[3:]:
            try:
                n = int(num[2:], base=16)
            except:
                raise ValueError('Invalid immediate number input.\nLocation:PC='+hex(pc-1))
            return n <= high and n >= low
        elif (num.startswith('x') or num.startswith('X')) and all(i in '-0123456789abcdefABCDEF' for i in num[1:]) and '-' not in num[2:]:
            try:
                n = int(num[1:], base=16)
            except:
                raise ValueError('Invalid immediate number input.\nLocation:PC='+hex(pc-1))
            return n <= high and n >= low
        elif (num.startswith('#')) and all(i in '-0123456789' for i in num[1:]) and '-' not in num[2:]:
            try:
                n = int(num[1:], base=10)
            except:
                raise ValueError('Invalid immediate number input.\nLocation:PC='+hex(pc-1))
            return n <= high and n >= low
        else:
            try:
                n = int(num)
                return n <= high and n >= low
            except ValueError:
                raise ValueError('Invalid immediate number input.\nLocation:PC='+hex(pc-1)) from None

    def get_immediate(self, word, pc,mask=0xFFFF):
        if (word.startswith('0x') or word.startswith('0X')) and all(i in '-0123456789abcdefABCDEF' for i in word[2:]) and '-' not in word[3:]:
            return int(word[2:], base=16) & mask
        elif ((word.startswith('x') or word.startswith('X')) and all(i in '-0123456789abcdefABCDEF' for i in word[1:]) and '-' not in word[2:]):
            return int(word[1:], base=16) & mask
        elif word.startswith('#'):
            return int(word[1:]) & mask
        
        else:
            try:
                return int(word)&mask
            except BaseException:
                raise ValueError('Invalid immedate.\nLocation:PC='+hex(pc-1))

    def regulate(self):
        with open(self.address, 'r+') as f:
            content = f.readlines()
            instructions=[]
            for instruction in content:
                a = instruction.strip().replace('\t', ' ').replace(',', ', ').split(' ')
                while '' in a:
                    a.remove('')
                flag = 0
                for i in range(0, len(a)):
                    if ',' in a[i]:
                        a[i] = a[i].replace(',','')
                    if ';' in a[i]:
                        flag = 1
                        break
                if flag:
                    a = a[:i]
                if len(a) != 0:
                    instructions.append(a)
            # print(a)
        return instructions

    def assemble(self):
        binary_code = []
        # pass one
        content = self.regulate()

        if content[0][0] != '.ORIG':
            print("Expected .ORIG but not found!\n")
            return None
        else:
            pc = int('0' + content[0][1], base=16)
            lc = pc
            if content[::-1][0][0] != '.END':
                print("Expected .END but not found!\n")
                return None

        self.symbol_table = {}
        # string_pattern = r'^'"."'$'
        for instruction in content:
            if instruction[0].upper() not in self.opcode_table and instruction[0] not in self.pseudo_ops:
                self.symbol_table[instruction[0]] = hex(lc)
                instruction.remove(instruction[0])
                if len(instruction) >= 2 and instruction[0] == '.BLKW':
                    lc += int(instruction[1])
                elif len(instruction) >= 2 and instruction[0] == '.STRINGZ':
                    lc += int(len(instruction[1])) - 1
                else:
                    lc += 1
            elif instruction[0] != '.ORIG' and instruction[0] != '.END':
                lc += 1
        # print(content)
        # print(self.symbol_table)
        
        # pass two

        for instruction in content:
            if len(instruction) < 1:
                raise SyntaxError('Invalid syntax.\nLocation:PC='+hex(pc-1))
            if instruction[0] in self.opcode_table.keys() or instruction[0].upper() in self.opcode_table.keys():
                pc += 1
                # print(instruction)
                if instruction[0] in self.op_instructions or instruction[0].upper() in self.op_instructions:
                    code = self.get_op_instruction(instruction, pc)
                    # print('0'*(16-len(bin(code)[2:]))+bin(code)[2:])
                elif instruction[0] in self.ctrl_instructions or instruction[0].upper() in self.ctrl_instructions:
                    code = self.get_ctrl_instruction(instruction, pc)
                    # print(instruction)
                    # print('0' * (16 - len(bin(code)[2:])) + bin(code)[2:])
                else:
                    code = self.get_data_movement_instruction(instruction, pc)
                    # print('0'*(16-len(bin(code)[2:]))+bin(code)[2:])
                binary_code.append('0'*(16-len(bin(code)[2:]))+bin(code)[2:])
            elif instruction[0] in self.pseudo_ops:
                if instruction[0] == '.ORIG':
                    code = pc
                    binary_code.append(
                        '0'*(16 - len(bin(code)[2:])) + bin(code)[2:])
                elif instruction[0] == '.FILL':
                    if len(instruction) > 3:
                        raise SyntaxError(
                            'The number of oprands is more than excepted.\nLocation:PC='+hex(pc-1))
                    code = self.get_immediate(instruction[1],pc)
                    pc += 1
                    binary_code.append(
                        '0'*(16 - len(bin(code)[2:])) + bin(code)[2:])
                elif instruction[0] == '.BLKW':
                    if len(instruction) > 2:
                        raise SyntaxError(
                            'The number of oprands is more than excepted.\nLocation:PC='+hex(pc-1))
                    pc += int(instruction[1])
                    code = '0' * 16             #TODO:blkw more than one address.
                    binary_code.append(code)
                elif instruction[0] == '.STRINGZ':
                    if len(instruction) > 2:
                        raise SyntaxError(
                            'The number of oprands is more than excepted.\nLocation:PC='+hex(pc-1))
                    if not (instruction[1].startswith(r'"') and instruction[1].endswith(r'"')):
                        raise SyntaxError(
                            'Invalid syntax.\nLocation:PC='+hex(pc-1))
                    else:
                        for i in range(1, len(instruction[1]) - 1):
                            pc += 1
                            binary_code.append('0'*(16-len(bin(ord(instruction[1][i]))[2:]))+bin(ord(instruction[1][i]))[2:])
                        pc += 1
                        binary_code.append('0' * 16)
                elif instruction[0] == '.END':
                    pass
                else:
                    raise SyntaxError('Invalid syntax.\nLocation:PC='+hex(pc-1))
            else:
                raise SyntaxError('Invalid syntax.\nLocation:PC='+hex(pc-1))
        # print(binary_code)
        with open(self.address.split('.')[0] + '.obj', 'wb') as f:
            for code in binary_code:
                f.write(six.int2byte(int(code[:8], base=2)))
                f.write(six.int2byte(int(code[8:], base=2)))
        # TODO: Location of error.
if __name__ == "__main__":
    try:
        Myassembler = Assembler(address=sys.argv[1])
    except BaseException:
        raise ValueError("The location of program is needed.") from None
    Myassembler.assemble()
