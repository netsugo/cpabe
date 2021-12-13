package co.junwei.cpabe;
import co.junwei.cpabe.policy.LangPolicy;
import it.unisa.dia.gas.jpbc.Element;

import java.io.*;
import java.security.NoSuchAlgorithmException;

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

    @Deprecated
    public void setup(String pubfile, String mskfile) throws IOException {
		BswabePub pub = new BswabePub();
		BswabeMsk msk = new BswabeMsk();
		Bswabe.setup(pub, msk);

		/* store BswabePub into mskfile */
		byte[] pub_byte = SerializeUtils.serializeBswabePub(pub);
		Common.spitFile(pubfile, pub_byte);

		/* store BswabeMsk into mskfile */
		byte[] msk_byte = SerializeUtils.serializeBswabeMsk(msk);
		Common.spitFile(mskfile, msk_byte);
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

    @Deprecated
	public void keygen(String pubfile, String prvfile, String mskfile, String attr_str) throws Exception {
		/* get BswabePub from pubfile */
		byte[] pub_byte = Common.suckFile(pubfile);

		/* get BswabeMsk from mskfile */
		byte[] msk_byte = Common.suckFile(mskfile);

		/* store BswabePrv into prvfile */
		byte[] prv_byte = keygen(pub_byte, msk_byte, attr_str);
		Common.spitFile(prvfile, prv_byte);
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

    @Deprecated
    public void enc(String pubfile, String policy, String inputfile, String encfile) throws Exception {
        /* get BswabePub from pubfile */
        byte[] pub_byte = Common.suckFile(pubfile);
        byte[] plt = Common.suckFile(inputfile);
        byte[] enc = enc(pub_byte, policy, plt).toByteArray();

        OutputStream os = new FileOutputStream(encfile);
        os.write(enc);
        os.close();
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

    @Deprecated
    public void dec(String pubfile, String prvfile, String encfile,	String decfile) throws Exception {
        /* get BswabePub from pubfile */
        byte[] pub_byte = Common.suckFile(pubfile);

        /* get BswabePrv form prvfile */
        byte[] prv_byte = Common.suckFile(prvfile);

        byte[] enc_byte = Common.suckFile(prvfile);
        ByteArrayInputStream is = new ByteArrayInputStream(enc_byte);
        byte[] dec = dec(pub_byte, prv_byte, is).toByteArray();

        FileOutputStream os = new FileOutputStream(decfile);
        os.write(dec);
    }
}
