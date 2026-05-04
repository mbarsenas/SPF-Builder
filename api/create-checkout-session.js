import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const origin = req.headers.origin || "http://localhost:5173";

  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    line_items: [
      {
        price_data: {
          currency: "usd",
          unit_amount: 500,
          product_data: {
            name: "Email DNS Audit Report",
          },
        },
        quantity: 1,
      },
    ],
    success_url: `${origin}?audit_paid=true`,
    cancel_url: `${origin}?audit_cancelled=true`,
  });

  res.status(200).json({ url: session.url });
}
