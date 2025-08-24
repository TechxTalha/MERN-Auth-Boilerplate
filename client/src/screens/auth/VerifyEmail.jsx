import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { App, Result, Button } from "antd";
import { Loader } from "../../animations/pageLoader/Loader";
import { verifyEmailToken } from "../../services/authServices";

const VerifyEmail = () => {
  const { message } = App.useApp();
  const navigate = useNavigate();
  const { token } = useParams();
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState(null);
  const [flag, setFlag] = useState(false);

  useEffect(() => {
    if (token && status !== "success") verify();
  }, []);

  const verify = async () => {
    try {
      const res = await verifyEmailToken(token);
      if (res.status === 200) {
        message.success(res.data.message || "Email verified successfully!");
        setStatus("success");
        navigate("/login");
      } else {
        message.error(res.data.message || "Verification failed!");
        setStatus("error");
      }
    } catch (err) {
      message.error(err.response?.data?.message || "Invalid or used token!");
      setStatus("error");
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader isLoading={true} />
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
      {status === "success" ? (
        <Result
          status="success"
          title="Email Verified!"
          subTitle="You will be redirected to the login page shortly."
          extra={[
            <Button
              type="primary"
              key="login"
              onClick={() => navigate("/login")}
            >
              Go to Login
            </Button>,
          ]}
        />
      ) : (
        <Result
          status="error"
          title="Verification Failed"
          subTitle="Your verification link may have been used or is invalid."
          extra={[
            <Button type="primary" key="home" onClick={() => navigate("/")}>
              Back to Home
            </Button>,
          ]}
        />
      )}
    </div>
  );
};

export default VerifyEmail;
