import nodemailer from 'nodemailer'

function createTransport() {
  const user = process.env.GMAIL_USER
  const pass = process.env.GMAIL_APP_PASSWORD
  if (!user || !pass) throw new Error('GMAIL_USER and GMAIL_APP_PASSWORD are required')
  return nodemailer.createTransport({ service: 'gmail', auth: { user, pass } })
}

export async function sendMagicLink(
  to: string,
  url: string,
  type: 'signin' | 'confirm' = 'signin',
): Promise<void> {
  const user = process.env.GMAIL_USER!
  const transport = createTransport()

  const isConfirm = type === 'confirm'
  const subject = isConfirm ? 'Confirm your NextGuard account' : 'Sign in to NextGuard'
  const heading = isConfirm ? 'Confirm your account' : 'Sign in to your account'
  const btnText = isConfirm ? 'Confirm Account →' : 'Sign in to NextGuard →'
  const note = isConfirm
    ? 'This confirmation link expires in <strong style="color:#e5e5e5">15 minutes</strong>.'
    : 'This sign-in link expires in <strong style="color:#e5e5e5">15 minutes</strong> and can only be used once.'

  await transport.sendMail({
    from: `NextGuard <${user}>`,
    to,
    subject,
    html: `
<div style="font-family:system-ui,sans-serif;max-width:520px;margin:40px auto;background:#0d0d0d;border:1px solid #1a1a1a;border-radius:16px;padding:40px;color:#e5e5e5">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#3b82f6"/>
    </svg>
    <span style="font-weight:700;font-size:18px;color:#fff">NextGuard</span>
  </div>
  <div style="color:#555;font-size:12px;margin-bottom:32px;padding-bottom:20px;border-bottom:1px solid #1a1a1a">Enterprise L7 WAF</div>
  <h2 style="font-size:20px;font-weight:700;color:#fff;margin:0 0 12px">${heading}</h2>
  <p style="color:#737373;margin:0 0 24px;font-size:14px;line-height:1.6">${note}</p>
  <a href="${url}" style="display:inline-block;background:#3b82f6;color:#fff;padding:13px 28px;border-radius:10px;text-decoration:none;font-weight:600;font-size:15px;margin-bottom:24px">${btnText}</a>
  <p style="color:#555;margin:0 0 6px;font-size:12px">If you didn't request this, you can safely ignore this email.</p>
  <p style="color:#333;margin:0;font-size:11px;word-break:break-all">Or copy: ${url}</p>
</div>`,
  })
}
