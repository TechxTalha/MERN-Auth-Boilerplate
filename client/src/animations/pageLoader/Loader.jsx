import loadingAnimation from "./loadingAnimation.json";
import Lottie from "lottie-react";

export function Loader({ isLoading }) {
  return (
    <>
      {isLoading && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            width: "100%",
            height: "100%",
            backgroundColor: "rgba(255,255,255,0.8)",
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            zIndex: 999,
            pointerEvents: "auto",
          }}
        >
          <Lottie
            animationData={loadingAnimation}
            loop={true}
            autoplay={true}
            style={{ height: 250, width: 250 }}
          />
        </div>
      )}
    </>
  );
}
