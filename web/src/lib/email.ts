import nodemailer from 'nodemailer'

export async function sendMagicLink(to: string, magicUrl: string): Promise<void> {
  const user = process.env.GMAIL_USER
  const pass = process.env.GMAIL_APP_PASSWORD

  if (!user || !pass) {
    throw new Error('GMAIL_USER and GMAIL_APP_PASSWORD environment variables are required')
  }

  const transport = nodemailer.createTransport({
    service: 'gmail',
    auth: { user, pass },
  })

  await transport.sendMail({
    from: `NextGuard <${user}>`,
    to,
    subject: 'Sign in to NextGuard',
    html: `
<div style="font-family:system-ui,sans-serif;max-width:500px;margin:40px auto;background:#0a0a0a;border:1px solid #1a1a1a;border-radius:12px;padding:32px;color:#e5e5e5">
  <div style="font-size:24px;margin-bottom:4px">🛡️ NextGuard</div>
  <div style="color:#666;font-size:13px;margin-bottom:24px">Enterprise L7 WAF</div>
  <p style="color:#a3a3a3;margin:0 0 20px;font-size:14px;line-height:1.6">
    Click the button below to sign in to your NextGuard dashboard.<br>
    This link expires in <strong style="color:#e5e5e5">15 minutes</strong> and can only be used once.
  </p>
  <a href="${magicUrl}" style="display:inline-block;background:#3b82f6;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:15px">
    Sign in to NextGuard →
  </a>
  <p style="color:#555;margin:20px 0 0;font-size:12px">
    If you didn't request this, you can safely ignore this email.
  </p>
  <p style="color:#333;margin:8px 0 0;font-size:11px;word-break:break-all">
    Or copy this link: ${magicUrl}
  </p>
</div>`,
  })
}
