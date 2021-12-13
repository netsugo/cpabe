package co.junwei.cpabe;

import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.util.UUID;

public class CpabeDemo {
	static String policy = "foo bar fim 2of3 baf 1of2";

	static String student_attr = "objectClass:inetOrgPerson objectClass:organizationalPerson "
			+ "sn:student2 cn:student2 uid:student2 userPassword:student2 "
			+ "ou:idp o:computer mail:student2@sdu.edu.cn title:student";

	static String student_policy = "sn:student2 cn:student2 uid:student2 3of3";

	@Test
	public void demo() throws Exception {
		policy = student_policy;

		Cpabe test = new Cpabe();

		byte[][] setup = test.setup();
		byte[] publicKey = setup[Cpabe.PUBKEY];
		byte[] masterKey = setup[Cpabe.MASTER];

		byte[] privateKey = test.keygen(publicKey, masterKey, student_attr);

		String uuid = UUID.randomUUID().toString();

		byte[] enc = test.enc(publicKey, policy, uuid.getBytes()).toByteArray();
		String dec = test.dec(publicKey, privateKey, new ByteArrayInputStream(enc)).toString();

		Assert.assertEquals(uuid, dec);
	}
}
