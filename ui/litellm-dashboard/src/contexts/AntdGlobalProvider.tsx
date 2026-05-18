"use client";

import React, { useEffect, useRef } from "react";
import { notification, message } from "antd";
import { setNotificationInstance } from "@/components/molecules/notifications_manager";
import { setMessageInstance } from "@/components/molecules/message_manager";

const ANTD_COMPAT_WARNING = "antd v5 support React is 16 ~ 18";

export default function AntdGlobalProvider({ children }: { children: React.ReactNode }) {
  const [notificationApi, notificationContextHolder] = notification.useNotification();
  const [messageApi, messageContextHolder] = message.useMessage();
  const initialized = useRef(false);

  useEffect(() => {
    if (process.env.NODE_ENV !== "development") {
      return;
    }

    const originalConsoleError = console.error;
    console.error = (...args) => {
      const message = args.map(String).join(" ");
      if (message.includes(ANTD_COMPAT_WARNING)) {
        return;
      }

      originalConsoleError(...args);
    };

    return () => {
      console.error = originalConsoleError;
    };
  }, []);

  useEffect(() => {
    if (!initialized.current) {
      setNotificationInstance(notificationApi);
      setMessageInstance(messageApi);
      initialized.current = true;
    }
  }, [notificationApi, messageApi]);

  return (
    <>
      {notificationContextHolder}
      {messageContextHolder}
      {children}
    </>
  );
}



