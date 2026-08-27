import { LegalLayout } from "../legal-layout";

export default function SecurityPage() {
  return <LegalLayout title="Security & review status" summary="Whisper uses end-to-end encryption and publishes its security boundaries honestly. Independent review is pending.">
    <section>
      <h2>Current status</h2>
      <p>Whisper 0.10 has a maintainer-reviewed threat model, hardened app-owned email sessions, optional Google OpenID Connect, a cryptographic implementation inventory, automated dependency and code scanning, an authorization-gated penetration probe, and an incident-response plan. These controls improve reviewability; they are not a third-party certification.</p>
      <p><strong>Whisper and its TypeScript MLS integration have not completed an independent security audit or independent penetration test.</strong> Do not use this release for high-risk or life-safety communications.</p>
    </section>
    <section>
      <h2>What encryption protects</h2>
      <p>Direct-chat messages use RFC 9420 MLS. Locally attached media is encrypted in the browser before upload. The service stores ciphertext and the routing, membership, timing, size, broad media-kind, retention, and abuse metadata needed to operate the product.</p>
      <p>A compromised browser, extension, device, or same-origin script can read plaintext while you use the app. Recipients can also copy content after decryption. Online GIF search is a separate provider boundary.</p>
    </section>
    <section>
      <h2>Verification and response</h2>
      <p>Compare conversation safety numbers with your contact through another channel. Remove devices you no longer control, keep recovery keys offline, and treat decrypted downloads as untrusted files.</p>
      <p>Security findings should be reported privately to the repository owner with the affected version, impact, and minimal reproduction evidence. Do not include real user data, message content, private keys, recovery codes, or access tokens.</p>
    </section>
    <section>
      <h2>Independent-review requirement</h2>
      <p>An independent claim requires a separate qualified reviewer, an exact commit and lockfile scope, documented methodology and exclusions, remediation of material findings, and a retest. Whisper will publish the reviewed version and residual risks when that work is complete.</p>
    </section>
  </LegalLayout>;
}
