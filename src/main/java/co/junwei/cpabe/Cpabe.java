package co.junwei.cpabe;
import co.junwei.cpabe.policy.LangPolicy;
import it.unisa.dia.gas.jpbc.Element;

import java.io.*;

import co.junwei.bswabe.Bswabe;
import co.junwei.bswabe.BswabeCph;
import co.junwei.bswabe.BswabeCphKey;
import co.junwei.bswabe.BswabeElementBoolean;
import co.junwei.bswabe.BswabeMsk;
import co.junwei.bswabe.BswabePrv;
import co.junwei.bswabe.BswabePub;
import co.junwei.bswabe.SerializeUtils;

public class Cpabe {
    public static int PUBKEY = 0;
    public static int MASTER = 1;

    public byte[][] setup() {
        BswabePub pub = new BswabePub();
        BswabeMsk msk = new BswabeMsk();
        Bswabe.setup(pub, msk);

        /* store BswabePub into mskfile */
        byte[] pub_byte = SerializeUtils.serializeBswabePub(pub);

        /* store BswabeMsk into mskfile */
        byte[] msk_byte = SerializeUtils.serializeBswabeMsk(msk);

        return new byte[][]{pub_byte,msk_byte};
    }

    public byte[] keygen(byte[] pub_byte, byte[] msk_byte, String attr_str) throws Exception {
        /* get BswabePub from pubfile */
        BswabePub pub = SerializeUtils.unserializeBswabePub(pub_byte);

        /* get BswabeMsk from mskfile */
        BswabeMsk msk = SerializeUtils.unserializeBswabeMsk(pub, msk_byte);

        String[] attr_arr = LangPolicy.parseAttribute(attr_str);
        BswabePrv prv = Bswabe.keygen(pub, msk, attr_arr);

        /* store BswabePrv into prvfile */
        return SerializeUtils.serializeBswabePrv(prv);
    }

    public ByteArrayOutputStream enc(byte[] pub_byte, String policy, byte[] plain) throws Exception {
        /* get BswabePub from pubfile */
        BswabePub pub = SerializeUtils.unserializeBswabePub(pub_byte);

        BswabeCphKey keyCph = Bswabe.enc(pub, policy);
        BswabeCph cph = keyCph.cph;
        Element m = keyCph.key;

        if (cph == null) {
            throw new CpabeException("Encryption error: m = " + m);
        }

        byte[] cphBuf = SerializeUtils.bswabeCphSerialize(cph);

        /* read file to encrypted */
        byte[] aesBuf = AESCoder.encrypt(m.toBytes(), plain);

        return Common.writeCpabeData(new byte[0], cphBuf, aesBuf);
    }

	public ByteArrayOutputStream dec(byte[] pub_byte, byte[] prv_byte, ByteArrayInputStream enc_byte) throws Exception {
        /* get BswabePub from pubfile */
        BswabePub pub = SerializeUtils.unserializeBswabePub(pub_byte);

		/* read ciphertext */
        byte[][] tmp = Common.readCpabeData(enc_byte);
        byte[] aesBuf = tmp[0];
        byte[] cphBuf = tmp[1];
        BswabeCph cph = SerializeUtils.bswabeCphUnserialize(pub, cphBuf);

		/* get BswabePrv form prvfile */
        BswabePrv prv = SerializeUtils.unserializeBswabePrv(pub, prv_byte);

		BswabeElementBoolean beb = Bswabe.dec(pub, prv, cph);
		System.err.println("e = " + beb.e.toString());
		if (beb.b) {
            byte[] plt = AESCoder.decrypt(beb.e.toBytes(), aesBuf);
            ByteArrayOutputStream os = new ByteArrayOutputStream(plt.length);
            os.write(plt);
            return os;
		} else {
			throw new CpabeException("Decryption error: e = " + beb.e);
		}
	}
}
