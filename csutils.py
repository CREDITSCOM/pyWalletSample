import math

class Utils:
    
    @staticmethod
    def kTen(index):
        kTensPows = [1e-18, 1e-17, 1e-16, 1e-15, 1e-14, 1e-13, 1e-12, 1e-11, 1e-10, 1e-9, 1e-8, 1e-7, 1e-6, 1e-5, 1e-4, 1e-3,
                        1e-2,  1e-1,  1.,    1e1,   1e2,   1e3,   1e4,   1e5,   1e6,   1e7,  1e8,  1e9,  1e10, 1e11, 1e12, 1e13]
        if index >=0 and index < 32:
            return kTensPows[index]
        else:
            return 0

    @staticmethod
    def fee_to_double(fee):
        sign = -1. if int(fee / 32768) != 0 else 1.
        fee_double_ = sign * float(fee % 1024) * 1. / 1024.  * Utils.kTen(int(fee % 32768 / 1024))
        return fee_double_

    @staticmethod
    def double_to_fee(value):
        fee_comission = 0
        a = True
        if value < 0.:
            fee_comission += 32768
        else:
            fee_comission += (32768 if value < 0. else 0)
            value = math.fabs(value)
            expf = (0. if value == 0. else math.log10(value))
            expi = int(expf + 0.5 if expf >= 0. else expf - 0.5)
            value /= math.pow(10, expi)
            if value >= 1.:
                value *= 0.1
                expi += 1
            fee_comission += int(1024*(expi + 18))
            fee_comission += int(value * 1024)
        return fee_comission
