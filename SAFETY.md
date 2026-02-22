# Safety and Legal Guidelines

## ⚠️ CRITICAL WARNINGS ⚠️

### Legal Compliance

**THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.**

By using this honeypot platform, you acknowledge and agree that:

1. **You are solely responsible** for ensuring compliance with all applicable laws and regulations in your jurisdiction.

2. **Unauthorized deployment** of this software on networks you do not own or have explicit written permission to test is **ILLEGAL** and may result in:
   - Criminal prosecution
   - Civil liability
   - Violation of computer fraud and abuse laws
   - Breach of terms of service agreements

3. **The authors and contributors** of this software are not responsible for any misuse, illegal deployment, or consequences resulting from the use of this software.

### Ethical Use

This honeypot platform should **ONLY** be used for:

- ✅ Authorized security research
- ✅ Educational purposes in controlled environments
- ✅ Academic study of attack patterns
- ✅ Threat intelligence gathering on your own networks
- ✅ Security awareness training

**DO NOT** use this software for:

- ❌ Unauthorized access to systems
- ❌ Network penetration without permission
- ❌ Any illegal activities
- ❌ Deception or fraud
- ❌ Production network deployment without proper isolation

### Network Isolation Requirements

**MANDATORY:** This honeypot must be deployed in an isolated network environment:

1. **No Production Access**: Never deploy on production networks or networks containing production systems.

2. **Isolated Network**: Use Docker's internal networking or a dedicated isolated VLAN.

3. **No Egress**: The honeypot network should have NO outbound internet access except for:
   - Controlled updates (if explicitly configured)
   - Alert delivery (webhooks/Slack/Telegram)

4. **Firewall Rules**: Implement strict firewall rules to prevent:
   - Access to internal networks
   - Access to other systems
   - Unauthorized data exfiltration

### Data Collection and Privacy

- All attacker interactions are logged and may contain sensitive information
- Logs may be used for legal purposes
- Ensure compliance with data protection regulations (GDPR, etc.)
- Store logs securely and limit access
- Implement proper data retention policies

### Incident Response

If you detect unauthorized access attempts:

1. **Document everything**: Preserve all logs, packet captures, and session recordings
2. **Do not engage**: Do not interact with attackers
3. **Report**: Report incidents to appropriate authorities if required by law
4. **Isolate**: Ensure the honeypot remains isolated from other systems

### Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### Acknowledgment

By deploying or using this software, you acknowledge that you have read, understood, and agree to comply with all safety guidelines and legal requirements outlined in this document.

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**




