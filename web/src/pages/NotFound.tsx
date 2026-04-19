import { Link } from "react-router-dom";

export default function NotFound() {
  return (
    <div className="mx-auto max-w-lg text-center">
      <p className="text-xl font-bold">Not found.</p>
      <Link className="mt-4 inline-block text-sm" to="/">
        Back to dashboard
      </Link>
    </div>
  );
}
