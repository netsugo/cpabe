package co.junwei.bswabe;

import org.junit.Assert;
import org.junit.Test;

public class BswabeTest {
    @Test
    public void prv() throws Exception {
        BswabePub pub = new BswabePub();
        BswabeMsk msk = new BswabeMsk();
        Bswabe.setup(pub, msk);

        String policy = "foo bar fim 2of3 baf 1of2";
        BswabeCphKey crypted = Bswabe.enc(pub, policy);
        BswabeCph cph = crypted.cph;

        String[] attr = {"baf", "fim1", "fim", "foo"};
        BswabePrv prv = Bswabe.keygen(pub, msk, attr);

        BswabeElementBoolean result = Bswabe.dec(pub, prv, cph);
        Assert.assertTrue(result.b && result.e.equals(crypted.key));
    }

    @Test
    public void prvDelegateOk() throws Exception {
        BswabePub pub = new BswabePub();
        BswabeMsk msk = new BswabeMsk();
        Bswabe.setup(pub, msk);

        String policy = "foo bar fim 2of3 baf 1of2";
        BswabeCphKey crypted = Bswabe.enc(pub, policy);
        BswabeCph cph = crypted.cph;

        String[] attr = {"baf", "fim1", "fim", "foo"};
        BswabePrv prv = Bswabe.keygen(pub, msk, attr);

        String[] attr_delegate_ok = {"fim", "foo"};
        BswabePrv prv_delegate_ok = Bswabe.delegate(pub, prv, attr_delegate_ok);

        BswabeElementBoolean result = Bswabe.dec(pub, prv_delegate_ok, cph);
        Assert.assertTrue(result.b && result.e.equals(crypted.key));
    }

    @Test
    public void prvDelegateKo() throws Exception {
        BswabePub pub = new BswabePub();
        BswabeMsk msk = new BswabeMsk();
        Bswabe.setup(pub, msk);

        String policy = "foo bar fim 2of3 baf 1of2";
        BswabeCphKey crypted = Bswabe.enc(pub, policy);
        BswabeCph cph = crypted.cph;

        String[] attr = {"baf", "fim1", "fim", "foo"};
        BswabePrv prv = Bswabe.keygen(pub, msk, attr);

        String[] attr_delegate_ko = {"fim"};
        BswabePrv prv_delegate_ko = Bswabe.delegate(pub, prv, attr_delegate_ko);

        BswabeElementBoolean result = Bswabe.dec(pub, prv_delegate_ko, cph);
        Assert.assertFalse(result.b && result.e.equals(crypted.key));
    }
}
