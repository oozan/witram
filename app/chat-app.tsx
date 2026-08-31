"use client";

/* eslint-disable @next/next/no-img-element, jsx-a11y/media-has-caption -- decrypted object URLs cannot use the image optimizer, and private user media has no server-side caption track */

import { FormEvent, useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import Image from "next/image";
import { decryptMessage, encryptMessage } from "./client-crypto";
import {
  bytesToBase64,
  createEncryptedThumbnail,
  createMediaKey,
  decryptMediaBlob,
  encryptMediaBlob,
  isAttachmentDescriptor,
  validateMediaFile,
  type AttachmentDescriptor,
  type MediaRetention,
} from "./media-crypto";
import {
  cacheSentMlsMessage,
  addMlsGroupMember,
  acceptDeviceLinkCode,
  beginDeviceLink,
  claimDeviceLink,
  confirmDeviceLink,
  createEncryptedBackup,
  createMlsConversation,
  decryptMlsMessage,
  encryptMlsMessage,
  ensureMlsDevice,
  getMlsSessionStatus,
  getSafetyNumber,
  inspectDeviceLink,
  joinMlsConversation,
  listAccountDevices,
  markSafetyNumberVerified,
  rotateMlsEpoch,
  provisionDeviceToConversations,
  removeMlsGroupMember,
  restoreEncryptedBackup,
  revokeDevice,
  syncMlsEvents,
} from "./mls-crypto";

type Message = {
  id: number | string;
  text: string;
  gif?: string;
  gifUrl?: string;
  gifPreviewUrl?: string;
  time: string;
  mine?: boolean;
  status?: "read" | "sent" | "failed";
  replyTo?: string;
  replyToId?: string;
  reactions?: string[];
  edited?: boolean;
  deleted?: boolean;
  attachment?: AttachmentDescriptor;
};

type OnlineGif = {
  id: string;
  label: string;
  url: string;
  previewUrl: string;
  width: number;
  height: number;
  provider: "Tenor";
};

type DecodedStoredContent =
  | { recordType: "message"; text: string; gif?: string; gifUrl?: string; gifPreviewUrl?: string; replyTo?: string; replyToId?: string; attachment?: AttachmentDescriptor }
  | { recordType: "reaction"; targetId: string; emoji: string; active: boolean }
  | { recordType: "edit"; targetId: string; text: string }
  | { recordType: "delete"; targetId: string };

type Chat = {
  id: string;
  name: string;
  initials: string;
  preview: string;
  time: string;
  unread?: number;
  online?: boolean;
  pinned?: boolean;
  muted?: boolean;
  archived?: boolean;
  color: string;
  messages: Message[];
  kind?: "direct" | "group" | "saved";
  persisted?: boolean;
  memberIds?: string[];
  role?: "owner" | "member";
};

type CurrentUser = { id: string; email: string; displayName: string };
type Person = { id: string; email: string; displayName: string; createdAt?: string };
type ContactInvitation = { id: string; person: Person; createdAt: string };
type SocialState = { contacts: Person[]; incoming: ContactInvitation[]; outgoing: ContactInvitation[]; blocked: Person[] };
type DeviceSecurityState = { localDeviceId: string | null; devices: Array<{ id: string; name: string; updatedAt: string; current: boolean }>; backupUpdatedAt: string | null; canApproveLinks: boolean };
type ActiveSession = { id: string; fingerprint: string; current: boolean; createdAt: string; lastSeenAt: string; expiresAt: string };
type PushState = { supported: boolean; configured: boolean; enabled: boolean; permission: NotificationPermission };
type ColorPalette = "gold" | "emerald" | "sapphire" | "crimson" | "amethyst";

const colorPalettes: Array<{ id: ColorPalette; name: string; note: string }> = [
  { id: "gold", name: "Black Card", note: "Default" },
  { id: "emerald", name: "Night Vision", note: "Emerald" },
  { id: "sapphire", name: "Deep Cover", note: "Sapphire" },
  { id: "crimson", name: "Red Notice", note: "Crimson" },
  { id: "amethyst", name: "Cipher", note: "Amethyst" },
];

const initialChats: Chat[] = [
  {
    id: "saved",
    name: "Saved Messages",
    initials: "★",
    preview: "Your private notes stay encrypted",
    time: "Now",
    color: "cyan",
    kind: "saved",
    messages: [],
  },
];

const formatTime = () =>
  new Intl.DateTimeFormat("en", { hour: "2-digit", minute: "2-digit", hour12: false }).format(new Date());

const MAX_MESSAGE_LENGTH = 12_000;

async function readApiResponse<T>(response: Response): Promise<T & { error?: string }> {
  const body = await response.text();
  if (!body) {
    return { error: response.ok ? "The server returned an empty response" : `Request failed (${response.status})` } as T & { error?: string };
  }
  try {
    return JSON.parse(body) as T & { error?: string };
  } catch {
    return { error: response.ok ? "The server returned an invalid response" : `Request failed (${response.status})` } as T & { error?: string };
  }
}

const emojiGroups = [
  { name: "Smileys", icon: "☺", emojis: ["😀", "😃", "😄", "😁", "😂", "🤣", "😊", "😍", "🥰", "😘", "😎", "🤩", "🥳", "🤗", "🤔", "🫡", "🥹", "😴", "😭", "😤", "🤯", "😱", "🙈", "🫠"] },
  { name: "Gestures", icon: "✌", emojis: ["👋", "🤚", "🖐️", "✋", "👌", "🤌", "🤏", "✌️", "🤞", "🫶", "🤟", "🤙", "👈", "👉", "👆", "👇", "👍", "👎", "👏", "🙌", "🤝", "🙏", "💪", "🫵"] },
  { name: "Hearts", icon: "♡", emojis: ["❤️", "🧡", "💛", "💚", "🩵", "💙", "💜", "🖤", "🤍", "🤎", "💔", "❤️‍🔥", "❤️‍🩹", "💕", "💞", "💓", "💗", "💖", "💘", "💝", "💟", "❣️", "💌", "💋"] },
  { name: "Fun", icon: "✦", emojis: ["✨", "🔥", "🎉", "🎊", "🎈", "🎁", "🏆", "⚡", "💫", "⭐", "🌈", "☀️", "🌙", "🌊", "🌸", "🍀", "🚀", "💯", "✅", "💡", "🎵", "📸", "☕", "🍕"] },
];

const gifs = [
  { id: "celebrate", label: "Celebrate!", emoji: "🎉", colors: ["#7057db", "#ff7ca8"] },
  { id: "love-it", label: "Love it", emoji: "😍", colors: ["#ef5a70", "#ffb06d"] },
  { id: "lets-go", label: "Let's go!", emoji: "🚀", colors: ["#116e8b", "#53c9a8"] },
  { id: "wow", label: "WOW", emoji: "🤯", colors: ["#ce653f", "#f4ca64"] },
  { id: "thank-you", label: "Thank you", emoji: "🫶", colors: ["#9859a8", "#ef9ab0"] },
  { id: "good-job", label: "Good job!", emoji: "👏", colors: ["#2871a5", "#6bbbd2"] },
  { id: "hello", label: "Hello!", emoji: "👋", colors: ["#168568", "#8bcf8e"] },
  { id: "coffee", label: "Coffee?", emoji: "☕", colors: ["#765448", "#c99b73"] },
];

function withChatPreferences(chat: Chat): Chat {
  try {
    const stored = localStorage.getItem(`whisper-chat-preferences:${chat.id}`);
    if (!stored) return chat;
    const preferences = JSON.parse(stored) as { pinned?: unknown; muted?: unknown; archived?: unknown; unread?: unknown };
    return {
      ...chat,
      pinned: typeof preferences.pinned === "boolean" ? preferences.pinned : chat.pinned,
      muted: typeof preferences.muted === "boolean" ? preferences.muted : chat.muted,
      archived: typeof preferences.archived === "boolean" ? preferences.archived : chat.archived,
      unread: typeof preferences.unread === "number" && preferences.unread >= 0 ? preferences.unread : chat.unread,
    };
  } catch {
    return chat;
  }
}

function decodeStoredMessage(value: string): DecodedStoredContent {
  if (value.startsWith("[attachment]")) {
    try {
      const attachment = JSON.parse(value.slice(12)) as unknown;
      if (isAttachmentDescriptor(attachment)) return { recordType: "message", text: attachment.name, attachment };
    } catch {
      return { recordType: "message", text: "Encrypted attachment" };
    }
  }
  if (value.startsWith("[edit]")) {
    try {
      const data = JSON.parse(value.slice(6)) as { targetId?: unknown; text?: unknown };
      if (typeof data.targetId === "string" && typeof data.text === "string" && data.text.trim()) {
        return { recordType: "edit", targetId: data.targetId, text: data.text };
      }
    } catch {
      // Invalid encrypted control records are ignored as ordinary messages below.
    }
  }
  if (value.startsWith("[delete]")) {
    try {
      const data = JSON.parse(value.slice(8)) as { targetId?: unknown };
      if (typeof data.targetId === "string") return { recordType: "delete", targetId: data.targetId };
    } catch {
      // Invalid encrypted control records are ignored as ordinary messages below.
    }
  }
  if (value.startsWith("[reaction]")) {
    try {
      const data = JSON.parse(value.slice(10)) as { targetId?: unknown; emoji?: unknown; active?: unknown };
      if (typeof data.targetId === "string" && typeof data.emoji === "string" && typeof data.active === "boolean") {
        return { recordType: "reaction", targetId: data.targetId, emoji: data.emoji, active: data.active };
      }
    } catch {
      // Invalid encrypted control records are ignored as ordinary messages below.
    }
  }
  if (value.startsWith("[message]")) {
    try {
      const data = JSON.parse(value.slice(9)) as { text?: unknown; replyTo?: unknown; replyToId?: unknown };
      if (typeof data.text === "string" && typeof data.replyTo === "string") {
        return { recordType: "message", text: data.text, replyTo: data.replyTo, replyToId: typeof data.replyToId === "string" ? data.replyToId : undefined };
      }
    } catch {
      return { recordType: "message", text: "Encrypted message" };
    }
  }
  if (value.startsWith("[online-gif]")) {
    try {
      const data = JSON.parse(value.slice(12)) as { id: string; label: string; url: string; previewUrl: string };
      if (data.id && data.label && data.url && data.previewUrl) {
        return { recordType: "message", text: data.label, gif: `tenor-${data.id}`, gifUrl: data.url, gifPreviewUrl: data.previewUrl };
      }
    } catch {
      return { recordType: "message", text: "GIF" };
    }
  }
  const match = value.match(/^\[gif:([a-z0-9-]+)]\s*(.*)$/i);
  return match
    ? { recordType: "message", text: match[2], gif: match[1] }
    : { recordType: "message", text: value };
}

function MessageText({ text }: { text: string }) {
  const parts = text.split(/(https?:\/\/[^\s]+)/gi);
  return <p>{parts.map((part, index) => /^https?:\/\//i.test(part)
    ? <a key={`${part}-${index}`} href={part} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{part}</a>
    : part)}</p>;
}

function EncryptedAttachment({ attachment }: { attachment: AttachmentDescriptor }) {
  const [thumbnailUrl, setThumbnailUrl] = useState<string | null>(null);
  const [mediaUrl, setMediaUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!attachment.thumbnailIv || !attachment.thumbnailMime) return;
    const controller = new AbortController();
    let objectUrl: string | null = null;
    fetch(`/api/attachments/${encodeURIComponent(attachment.id)}?part=thumbnail`, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error(response.status === 410 ? "Media expired" : "Preview unavailable");
        const blob = await decryptMediaBlob(await response.arrayBuffer(), attachment.key, attachment.thumbnailIv!, attachment.thumbnailMime!);
        objectUrl = URL.createObjectURL(blob);
        setThumbnailUrl(objectUrl);
      })
      .catch((cause) => { if ((cause as Error).name !== "AbortError") setError(cause instanceof Error ? cause.message : "Preview unavailable"); });
    return () => { controller.abort(); if (objectUrl) URL.revokeObjectURL(objectUrl); };
  }, [attachment.id, attachment.key, attachment.thumbnailIv, attachment.thumbnailMime]);

  useEffect(() => () => { if (mediaUrl) URL.revokeObjectURL(mediaUrl); }, [mediaUrl]);

  async function loadOriginal() {
    if (mediaUrl) return mediaUrl;
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/attachments/${encodeURIComponent(attachment.id)}?part=original`);
      if (!response.ok) throw new Error(response.status === 410 ? "This media has expired" : "Encrypted media is unavailable");
      const blob = await decryptMediaBlob(await response.arrayBuffer(), attachment.key, attachment.iv, attachment.mime);
      const url = URL.createObjectURL(blob);
      setMediaUrl(url);
      return url;
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Media could not be decrypted");
      return null;
    } finally {
      setLoading(false);
    }
  }

  async function downloadFile() {
    const url = await loadOriginal();
    if (!url) return;
    const link = document.createElement("a");
    link.href = url;
    link.download = attachment.name;
    link.click();
  }

  const size = attachment.size >= 1024 * 1024 ? `${(attachment.size / 1024 / 1024).toFixed(1)} MB` : `${Math.ceil(attachment.size / 1024)} KB`;
  const expiry = attachment.expiresAt ? `deletes ${new Intl.DateTimeFormat("en", { month: "short", day: "numeric" }).format(new Date(attachment.expiresAt))}` : "kept until deleted";
  return <div className={`encrypted-attachment attachment-${attachment.kind}`}>
    {attachment.kind === "image" || attachment.kind === "gif" ? mediaUrl
      ? <img src={mediaUrl} alt={attachment.name} />
      : <button className="encrypted-media-preview" onClick={() => void loadOriginal()} disabled={loading}>{thumbnailUrl && <img src={thumbnailUrl} alt="Encrypted preview" />}<span>{loading ? "Decrypting…" : `View ${attachment.kind}`}</span></button>
      : attachment.kind === "video" ? mediaUrl
        ? <video src={mediaUrl} poster={thumbnailUrl ?? undefined} controls playsInline />
        : <button className="encrypted-media-preview" onClick={() => void loadOriginal()} disabled={loading}>{thumbnailUrl && <img src={thumbnailUrl} alt="Encrypted video preview" />}<span>{loading ? "Decrypting…" : "Play video"}</span></button>
        : attachment.kind === "audio" ? mediaUrl
          ? <audio src={mediaUrl} controls />
          : <button className="encrypted-audio-load" onClick={() => void loadOriginal()} disabled={loading}><span>◉</span>{loading ? "Decrypting audio…" : "Play encrypted audio"}</button>
          : <button className="encrypted-file-download" onClick={() => void downloadFile()} disabled={loading}><span>⇩</span><strong>{attachment.name}</strong><small>{loading ? "Decrypting…" : "Download and decrypt"}</small></button>}
    {attachment.kind !== "file" && <strong className="attachment-name">{attachment.name}</strong>}
    <small className="attachment-security">⌁ AES-256-GCM · {size} · {expiry}</small>
    {error && <span className="attachment-error">{error}</span>}
  </div>;
}

export function ChatApp({ currentUser }: { currentUser: CurrentUser }) {
  const [chats, setChats] = useState(initialChats);
  const [activeId, setActiveId] = useState("saved");
  const [query, setQuery] = useState("");
  const [conversationFilter, setConversationFilter] = useState<"all" | "unread" | "groups" | "saved" | "archived">("all");
  const [draft, setDraft] = useState("");
  const [showMediaPicker, setShowMediaPicker] = useState(false);
  const [showAttachmentMenu, setShowAttachmentMenu] = useState(false);
  const [mediaRetention, setMediaRetention] = useState<MediaRetention>("7d");
  const [mediaUploadState, setMediaUploadState] = useState<string | null>(null);
  const [recordingSeconds, setRecordingSeconds] = useState(0);
  const [pickerTab, setPickerTab] = useState<"emoji" | "gif">("emoji");
  const [emojiGroup, setEmojiGroup] = useState("Smileys");
  const [gifQuery, setGifQuery] = useState("");
  const [onlineGifs, setOnlineGifs] = useState<OnlineGif[]>([]);
  const [gifSearchState, setGifSearchState] = useState<"idle" | "loading" | "ready" | "unconfigured" | "error">("idle");
  const [reactionTarget, setReactionTarget] = useState<Message["id"] | null>(null);
  const [showInfo, setShowInfo] = useState(false);
  const [mobileChatOpen, setMobileChatOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [showNewChat, setShowNewChat] = useState(false);
  const [newChatMode, setNewChatMode] = useState<"direct" | "group">("direct");
  const [groupTitle, setGroupTitle] = useState("");
  const [groupMemberIds, setGroupMemberIds] = useState<string[]>([]);
  const [creatingChat, setCreatingChat] = useState(false);
  const [groupAction, setGroupAction] = useState(false);
  const [showAccount, setShowAccount] = useState(false);
  const [accountName, setAccountName] = useState(currentUser.displayName);
  const [inviteEmail, setInviteEmail] = useState("");
  const [social, setSocial] = useState<SocialState>({ contacts: [], incoming: [], outgoing: [], blocked: [] });
  const [socialLoading, setSocialLoading] = useState(true);
  const [socialAction, setSocialAction] = useState(false);
  const [reportTarget, setReportTarget] = useState<{ userId: string; name: string } | null>(null);
  const [reportCategory, setReportCategory] = useState("spam");
  const [reportDetails, setReportDetails] = useState("");
  const [syncState, setSyncState] = useState<"online" | "syncing" | "offline">("syncing");
  const [syncRevision, setSyncRevision] = useState(0);
  const [showChatSearch, setShowChatSearch] = useState(false);
  const [chatSearchQuery, setChatSearchQuery] = useState("");
  const [highlightedMessageId, setHighlightedMessageId] = useState<Message["id"] | null>(null);
  const [replyingTo, setReplyingTo] = useState<{ id: Message["id"]; text: string } | null>(null);
  const [messageMenuTarget, setMessageMenuTarget] = useState<Message["id"] | null>(null);
  const [editingMessage, setEditingMessage] = useState<{ id: Message["id"]; originalText: string; previousDraft: string } | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Message | null>(null);
  const [theme, setTheme] = useState<"light" | "dark">("dark");
  const [palette, setPalette] = useState<ColorPalette>("gold");
  const [showPalette, setShowPalette] = useState(false);
  const [compactMode, setCompactMode] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);
  const [showShortcutHelp, setShowShortcutHelp] = useState(false);
  const [showScrollLatest, setShowScrollLatest] = useState(false);
  const [pinnedMessageId, setPinnedMessageId] = useState<string | null>(null);
  const [mlsDeviceId, setMlsDeviceId] = useState<string | null>(null);
  const [mlsStatuses, setMlsStatuses] = useState<Record<string, { ready: boolean; epoch: number | null; verified: boolean }>>({});
  const [mlsError, setMlsError] = useState<Record<string, string>>({});
  const [safetyNumber, setSafetyNumber] = useState<string | null>(null);
  const [rotatingKeys, setRotatingKeys] = useState(false);
  const [deviceSecurity, setDeviceSecurity] = useState<DeviceSecurityState | null>(null);
  const [deviceAction, setDeviceAction] = useState(false);
  const [activeSessions, setActiveSessions] = useState<ActiveSession[]>([]);
  const [sessionAction, setSessionAction] = useState(false);
  const [pushState, setPushState] = useState<PushState>({ supported: false, configured: false, enabled: false, permission: "default" });
  const [pushAction, setPushAction] = useState(false);
  const [linkCodeInput, setLinkCodeInput] = useState("");
  const [linkRequest, setLinkRequest] = useState<{ code: string; status: string; confirmation: string | null } | null>(null);
  const [linkApproval, setLinkApproval] = useState<{ confirmation: string } | null>(null);
  const [recoveryCode, setRecoveryCode] = useState("");
  const [newRecoveryCode, setNewRecoveryCode] = useState<string | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const chatSearchRef = useRef<HTMLInputElement>(null);
  const messageSpaceRef = useRef<HTMLDivElement>(null);
  const messageRefs = useRef(new Map<string, HTMLDivElement>());
  const userAwayFromBottomRef = useRef(false);
  const mediaInputRef = useRef<HTMLInputElement>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const mediaChunksRef = useRef<Blob[]>([]);
  const mediaStreamRef = useRef<MediaStream | null>(null);
  const recordingTimerRef = useRef<number | null>(null);
  const recordingSecondsRef = useRef(0);

  const activeChat = chats.find((chat) => chat.id === activeId) ?? chats[0];
  const activeMlsStatus = mlsStatuses[activeChat.id];
  const awaitingKeyExchange = Boolean(activeChat.memberIds?.length) && !activeMlsStatus?.ready;
  const pinnedMessage = activeChat.messages.find((message) => String(message.id) === pinnedMessageId && !message.deleted);
  const visibleChats = useMemo(
    () => chats
      .filter((chat) => conversationFilter === "archived" ? Boolean(chat.archived) : !chat.archived)
      .filter((chat) => conversationFilter === "all" || conversationFilter === "archived" || (conversationFilter === "unread" ? Boolean(chat.unread) : conversationFilter === "groups" ? chat.kind === "group" : chat.kind === "saved"))
      .filter((chat) => chat.name.toLowerCase().includes(query.toLowerCase()))
      .sort((a, b) => Number(Boolean(b.pinned)) - Number(Boolean(a.pinned))),
    [chats, conversationFilter, query],
  );
  const chatSearchResults = useMemo(() => {
    const search = chatSearchQuery.trim().toLocaleLowerCase();
    if (!search) return [];
    return activeChat.messages.filter((message) => message.text.toLocaleLowerCase().includes(search)).slice().reverse().slice(0, 20);
  }, [activeChat.messages, chatSearchQuery]);

  useEffect(() => {
    let cancelled = false;
    ensureMlsDevice(currentUser)
      .then((device) => { if (!cancelled) setMlsDeviceId(device.deviceId); })
      .catch((error) => { if (!cancelled) setMlsError((current) => ({ ...current, device: error instanceof Error ? error.message : "Device key initialization failed" })); });
    return () => { cancelled = true; };
  }, [currentUser]);

  useEffect(() => () => {
    if (recordingTimerRef.current !== null) window.clearInterval(recordingTimerRef.current);
    if (mediaRecorderRef.current) mediaRecorderRef.current.onstop = null;
    mediaRecorderRef.current?.stop();
    mediaStreamRef.current?.getTracks().forEach((track) => track.stop());
  }, []);

  useEffect(() => {
    const peerId = activeChat.memberIds?.[0];
    if (!peerId || !activeChat.persisted || !mlsDeviceId) return;
    let cancelled = false;
    async function prepareSession() {
      try {
        await joinMlsConversation(currentUser, activeChat.id);
        await syncMlsEvents(activeChat.id, mlsDeviceId!);
        const status = await getMlsSessionStatus(activeChat.id);
        if (!cancelled) {
          setMlsStatuses((current) => ({ ...current, [activeChat.id]: status }));
          setMlsError((current) => ({ ...current, [activeChat.id]: "" }));
        }
      } catch (error) {
        if (!cancelled) setMlsError((current) => ({ ...current, [activeChat.id]: error instanceof Error ? error.message : "Secure key exchange failed" }));
      }
    }
    void prepareSession();
    const interval = window.setInterval(prepareSession, 5000);
    return () => { cancelled = true; window.clearInterval(interval); };
  }, [activeChat.id, activeChat.memberIds, activeChat.persisted, currentUser, mlsDeviceId]);

  useEffect(() => {
    const peerId = activeChat.kind === "direct" ? activeChat.memberIds?.[0] : undefined;
    if (!showInfo || !peerId || !activeMlsStatus?.ready) {
      setSafetyNumber(null);
      return;
    }
    let cancelled = false;
    getSafetyNumber(currentUser, peerId).then((number) => { if (!cancelled) setSafetyNumber(number); }).catch(() => { if (!cancelled) setSafetyNumber(null); });
    return () => { cancelled = true; };
  }, [activeChat.kind, activeChat.memberIds, activeMlsStatus?.ready, currentUser, showInfo]);

  useEffect(() => {
    if (!showAccount) return;
    let cancelled = false;
    listAccountDevices(currentUser).then((state) => { if (!cancelled) setDeviceSecurity(state); }).catch(() => { if (!cancelled) setDeviceSecurity(null); });
    return () => { cancelled = true; };
  }, [currentUser, showAccount]);

  useEffect(() => {
    if (!linkRequest || linkRequest.status === "claimed") return;
    let cancelled = false;
    async function pollLink() {
      try {
        const state = await inspectDeviceLink(currentUser);
        if (!cancelled && state) setLinkRequest((current) => current ? { ...current, status: state.status, confirmation: state.confirmation } : current);
      } catch {
        // The request remains visible so the user can retry or create a fresh code.
      }
    }
    void pollLink();
    const interval = window.setInterval(pollLink, 2500);
    return () => { cancelled = true; window.clearInterval(interval); };
  }, [currentUser, linkRequest]);

  useEffect(() => {
    const handleShortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setMobileChatOpen(false);
        window.setTimeout(() => searchRef.current?.focus(), 0);
      }
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "f") {
        event.preventDefault();
        setShowChatSearch(true);
        window.setTimeout(() => chatSearchRef.current?.focus(), 0);
      }
      if ((event.metaKey || event.ctrlKey) && event.key === "/") {
        event.preventDefault();
        setShowShortcutHelp((current) => !current);
      }
      if (event.key === "Escape") {
        setShowNewChat(false);
        setShowMediaPicker(false);
        setReactionTarget(null);
        setShowChatSearch(false);
        setReplyingTo(null);
        setMessageMenuTarget(null);
        setDeleteTarget(null);
        setShowShortcutHelp(false);
        setShowAccount(false);
        setShowPalette(false);
        setReportTarget(null);
        if (editingMessage) {
          setDraft(editingMessage.previousDraft);
          setEditingMessage(null);
        }
      }
    };
    window.addEventListener("keydown", handleShortcut);
    return () => window.removeEventListener("keydown", handleShortcut);
  }, [editingMessage]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const stored = localStorage.getItem(`whisper-draft:${initialChats[0].id}`);
      if (stored) setDraft(stored);
      const savedTheme = localStorage.getItem("whisper-theme-v2");
      if (savedTheme === "light" || savedTheme === "dark") setTheme(savedTheme);
      const savedPalette = localStorage.getItem("whisper-palette-v1");
      if (colorPalettes.some((option) => option.id === savedPalette)) setPalette(savedPalette as ColorPalette);
      setCompactMode(localStorage.getItem("whisper-density") === "compact");
      setReducedMotion(localStorage.getItem("whisper-reduced-motion") === "true");
      setChats((current) => current.map(withChatPreferences));
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function loadAccountAndContacts() {
      setSocialLoading(true);
      try {
        const [accountResponse, contactsResponse] = await Promise.all([fetch("/api/account"), fetch("/api/contacts")]);
        const accountPayload = await accountResponse.json() as { account?: CurrentUser; error?: string };
        const contactsPayload = await contactsResponse.json() as Partial<SocialState> & { error?: string };
        if (!accountResponse.ok || !contactsResponse.ok || !accountPayload.account) throw new Error(accountPayload.error ?? contactsPayload.error ?? "Account sync failed");
        if (cancelled) return;
        setAccountName(accountPayload.account.displayName);
        setSocial({ contacts: contactsPayload.contacts ?? [], incoming: contactsPayload.incoming ?? [], outgoing: contactsPayload.outgoing ?? [], blocked: contactsPayload.blocked ?? [] });
      } catch (error) {
        if (!cancelled) flash(error instanceof Error ? error.message : "Account sync failed");
      } finally {
        if (!cancelled) setSocialLoading(false);
      }
    }
    void loadAccountAndContacts();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!showAccount) return;
    let cancelled = false;
    void fetch("/api/auth/sessions")
      .then(async (response) => ({ response, payload: await readApiResponse<{ sessions?: ActiveSession[] }>(response) }))
      .then(({ response, payload }) => {
        if (!cancelled && response.ok && payload.sessions) setActiveSessions(payload.sessions);
      })
      .catch(() => { /* The account panel remains usable if session telemetry is temporarily unavailable. */ });
    return () => { cancelled = true; };
  }, [showAccount]);

  useEffect(() => {
    if (!showAccount) return;
    const supported = "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
    if (!supported) {
      setPushState({ supported: false, configured: false, enabled: false, permission: "default" });
      return;
    }
    let cancelled = false;
    void Promise.all([fetch("/api/push"), navigator.serviceWorker.getRegistration("/")])
      .then(async ([response, registration]) => ({ response, registration, payload: await readApiResponse<{ configured?: boolean }>(response) }))
      .then(async ({ response, registration, payload }) => {
        const subscription = await registration?.pushManager.getSubscription();
        if (!cancelled && response.ok) setPushState({ supported: true, configured: Boolean(payload.configured), enabled: Boolean(subscription), permission: Notification.permission });
      })
      .catch(() => { /* Notification controls remain safely disabled when configuration cannot be checked. */ });
    return () => { cancelled = true; };
  }, [showAccount]);

  useEffect(() => {
    const handleOnline = () => {
      setSyncState("syncing");
      setSyncRevision((current) => current + 1);
    };
    const handleOffline = () => setSyncState("offline");
    window.addEventListener("online", handleOnline);
    window.addEventListener("offline", handleOffline);
    return () => {
      window.removeEventListener("online", handleOnline);
      window.removeEventListener("offline", handleOffline);
    };
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => setPinnedMessageId(localStorage.getItem(`whisper-pinned-message:${activeId}`)), 0);
    return () => window.clearTimeout(timer);
  }, [activeId]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const key = `whisper-draft:${activeId}`;
      if (draft) localStorage.setItem(key, draft);
      else localStorage.removeItem(key);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [activeId, draft]);

  useEffect(() => {
    let cancelled = false;
    async function loadConversations() {
      try {
        const response = await fetch("/api/conversations");
        if (!response.ok) throw new Error("Conversation sync failed");
        const payload = await response.json() as {
          conversations?: Array<{ id: string; title: string; kind: Chat["kind"]; lastActivity: string; messageCount: number; memberIds: string[]; role: Chat["role"] }>;
        };
        if (cancelled) return;
        setChats((current) => {
          const known = new Set(current.map((chat) => chat.id));
          const restored = (payload.conversations ?? []).filter((chat) => !known.has(chat.id)).map((chat, index): Chat => withChatPreferences({
            id: chat.id,
            name: chat.title,
            initials: chat.title.split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase(),
            preview: chat.messageCount ? "Encrypted conversation" : "No messages yet",
            time: new Intl.DateTimeFormat("en", { month: "short", day: "numeric" }).format(new Date(chat.lastActivity)),
            color: ["green", "blue", "violet", "amber", "cyan", "coral"][index % 6],
            messages: [],
            kind: chat.kind,
            persisted: true,
            memberIds: chat.memberIds,
            role: chat.role,
          }));
          const serverChats = new Map((payload.conversations ?? []).map((chat) => [chat.id, chat]));
          const refreshed = current.map((chat) => serverChats.has(chat.id) ? { ...chat, memberIds: serverChats.get(chat.id)?.memberIds, role: serverChats.get(chat.id)?.role } : chat);
          return restored.length ? [...restored, ...refreshed] : refreshed;
        });
        setSyncState("online");
      } catch {
        if (!cancelled) setSyncState("offline");
      }
    }
    void loadConversations();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!showMediaPicker || pickerTab !== "gif") return;
    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      setGifSearchState("loading");
      try {
        const response = await fetch(`/api/gifs${gifQuery.trim() ? `?q=${encodeURIComponent(gifQuery.trim())}` : ""}`, { signal: controller.signal });
        const payload = await response.json() as { configured?: boolean; results?: OnlineGif[] };
        if (!payload.configured) {
          setOnlineGifs([]);
          setGifSearchState("unconfigured");
          return;
        }
        if (!response.ok) throw new Error("GIF search failed");
        setOnlineGifs(payload.results ?? []);
        setGifSearchState("ready");
      } catch (error) {
        if ((error as Error).name !== "AbortError") {
          setOnlineGifs([]);
          setGifSearchState("error");
        }
      }
    }, gifQuery.trim() ? 350 : 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [gifQuery, pickerTab, showMediaPicker]);

  useEffect(() => {
    let cancelled = false;

    async function loadEncryptedMessages() {
      setSyncState((current) => current === "offline" ? "syncing" : current);
      try {
        const response = await fetch(`/api/messages?conversationId=${encodeURIComponent(activeId)}`);
        if (!response.ok) throw new Error("Message sync failed");
        const payload = await response.json() as {
          messages?: Array<{ id: string; ciphertext: string; iv: string; createdAt: string; mine: boolean; protocol: string; epoch: number | null; senderDeviceId: string | null }>;
        };
        const decrypted: Array<{ id: string; createdAt: string; mine: boolean; content: DecodedStoredContent }> = [];
        for (const message of payload.messages ?? []) {
          try {
            const isMls = message.protocol === "mls-rfc9420-v1";
            if (isMls && mlsDeviceId) await syncMlsEvents(activeId, mlsDeviceId, message.epoch ?? undefined);
            const plaintext = isMls ? await decryptMlsMessage(activeId, message) : await decryptMessage(activeId, message);
            if (plaintext) decrypted.push({ ...message, content: decodeStoredMessage(plaintext) });
          } catch {
            // A message from an unavailable epoch remains hidden instead of exposing ciphertext.
          }
        }
        if (activeChat.memberIds?.length && mlsDeviceId) await syncMlsEvents(activeId, mlsDeviceId);
        if (cancelled || decrypted.length === 0) return;
        setChats((current) => current.map((chat) => {
          if (chat.id !== activeId) return chat;
          const known = new Set(chat.messages.map((message) => message.id));
          const restored = decrypted.flatMap((record): Message[] => {
            if (record.content.recordType !== "message" || known.has(record.id)) return [];
            return [{
              id: record.id,
              text: record.content.text,
              gif: record.content.gif,
              gifUrl: record.content.gifUrl,
              gifPreviewUrl: record.content.gifPreviewUrl,
              replyTo: record.content.replyTo,
              replyToId: record.content.replyToId,
              attachment: record.content.attachment,
              time: new Intl.DateTimeFormat("en", { hour: "2-digit", minute: "2-digit", hour12: false }).format(new Date(record.createdAt)),
              mine: record.mine,
              status: record.mine ? "read" : undefined,
            }];
          });
          let messages = restored.length ? [...chat.messages, ...restored] : chat.messages;
          for (const record of decrypted) {
            const control = record.content;
            if (control.recordType === "message") continue;
            messages = messages.map((message) => {
              if (String(message.id) !== control.targetId) return message;
              if (control.recordType === "edit") {
                return message.deleted ? message : { ...message, text: control.text, edited: true };
              }
              if (control.recordType === "delete") {
                return { ...message, text: "", gif: undefined, gifUrl: undefined, gifPreviewUrl: undefined, attachment: undefined, replyTo: undefined, replyToId: undefined, reactions: [], deleted: true };
              }
              const reactions = message.reactions ?? [];
              return {
                ...message,
                reactions: control.active
                  ? Array.from(new Set([...reactions, control.emoji]))
                  : reactions.filter((reaction) => reaction !== control.emoji),
              };
            });
          }
          return messages === chat.messages ? chat : { ...chat, messages };
        }));
        setSyncState("online");
      } catch {
        if (!cancelled) setSyncState("offline");
      }
    }

    void loadEncryptedMessages();
    const interval = window.setInterval(loadEncryptedMessages, 5000);
    return () => { cancelled = true; window.clearInterval(interval); };
  }, [activeChat.memberIds, activeId, mlsDeviceId, syncRevision]);

  useEffect(() => {
    const element = messageSpaceRef.current;
    if (element && !userAwayFromBottomRef.current) element.scrollTo({ top: element.scrollHeight, behavior: "smooth" });
  }, [activeChat.messages.length, activeId]);

  function handleMessageScroll() {
    const element = messageSpaceRef.current;
    if (!element) return;
    const awayFromBottom = element.scrollHeight - element.scrollTop - element.clientHeight > 160;
    userAwayFromBottomRef.current = awayFromBottom;
    setShowScrollLatest(awayFromBottom);
  }

  function scrollToLatest() {
    const element = messageSpaceRef.current;
    if (!element) return;
    userAwayFromBottomRef.current = false;
    setShowScrollLatest(false);
    element.scrollTo({ top: element.scrollHeight, behavior: reducedMotion ? "auto" : "smooth" });
  }

  function selectChat(id: string) {
    const nextDraft = localStorage.getItem(`whisper-draft:${id}`) ?? "";
    const selectedChat = chats.find((chat) => chat.id === id);
    if (selectedChat) persistChatPreferences(selectedChat, { unread: 0 });
    setActiveId(id);
    setDraft(nextDraft);
    setMobileChatOpen(true);
    setShowInfo(false);
    setShowChatSearch(false);
    setChatSearchQuery("");
    setReplyingTo(null);
    setMessageMenuTarget(null);
    setEditingMessage(null);
    userAwayFromBottomRef.current = false;
    setShowScrollLatest(false);
    setChats((current) => current.map((chat) => (chat.id === id ? { ...chat, unread: 0 } : chat)));
  }

  function openChatSearch() {
    setShowChatSearch(true);
    setShowInfo(false);
    window.setTimeout(() => chatSearchRef.current?.focus(), 0);
  }

  function focusMessage(messageId: Message["id"]) {
    setHighlightedMessageId(messageId);
    messageRefs.current.get(String(messageId))?.scrollIntoView({ behavior: "smooth", block: "center" });
    window.setTimeout(() => setHighlightedMessageId((current) => current === messageId ? null : current), 1800);
  }

  async function ensurePersistedChat(chat: Chat) {
    if (chat.persisted) return chat;
    const createResponse = await fetch("/api/conversations", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ title: chat.name, kind: chat.kind ?? "direct", memberIds: chat.memberIds ?? [] }),
    });
    const created = await readApiResponse<{ conversation?: { id: string } }>(createResponse);
    if (!createResponse.ok || !created.conversation) throw new Error(created.error ?? "Conversation creation failed");
    const secureChat = { ...chat, id: created.conversation.id, persisted: true };
    setActiveId(secureChat.id);
    setChats((current) => current.map((item) => item.id === chat.id ? { ...item, id: secureChat.id, persisted: true } : item));
    return secureChat;
  }

  async function persistEncryptedMessage(chat: Chat, message: Message) {
    let secureChat = chat;
    try {
      secureChat = await ensurePersistedChat(chat);

      const storedContent = message.attachment
        ? `[attachment]${JSON.stringify(message.attachment)}`
        : message.gifUrl
        ? `[online-gif]${JSON.stringify({ id: message.gif?.replace(/^tenor-/, ""), label: message.text, url: message.gifUrl, previewUrl: message.gifPreviewUrl ?? message.gifUrl })}`
        : message.gif ? `[gif:${message.gif}] ${message.text}`
          : message.replyTo ? `[message]${JSON.stringify({ text: message.text, replyTo: message.replyTo, replyToId: message.replyToId })}`
            : message.text;
      const usesMls = Boolean(secureChat.memberIds?.length);
      const encrypted = usesMls
        ? await encryptMlsMessage(secureChat.id, storedContent, String(message.id))
        : await encryptMessage(secureChat.id, storedContent);
      const response = await fetch("/api/messages", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          conversationId: secureChat.id,
          ...encrypted,
        }),
      });
      if (!response.ok) throw new Error("Message storage failed");
      const payload = await readApiResponse<{ message?: { id: string } }>(response);
      if (!payload.message) throw new Error(payload.error ?? "Message storage failed");
      if (usesMls) await cacheSentMlsMessage(String(message.id), payload.message.id, secureChat.id);
      setChats((current) => current.map((item) =>
        item.id === secureChat.id || item.id === chat.id
          ? { ...item, messages: item.messages.map((entry) => entry.id === message.id ? { ...entry, id: payload.message.id, status: "read" } : entry) }
          : item,
      ));
    } catch {
      setChats((current) => current.map((item) =>
        item.id === chat.id || item.id === secureChat.id
          ? { ...item, messages: item.messages.map((entry) => entry.id === message.id ? { ...entry, status: "failed" } : entry) }
          : item,
      ));
      flash("Message could not be stored securely. Tap to retry.");
    }
  }

  async function createConversation(contact: Person) {
    if (creatingChat) return;
    setCreatingChat(true);
    try {
      const response = await fetch("/api/conversations", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ title: contact.displayName, kind: "direct", memberIds: [contact.id] }),
      });
      const payload = await readApiResponse<{ conversation?: { id: string; title: string } }>(response);
      if (!response.ok || !payload.conversation) throw new Error(payload.error ?? "Conversation creation failed");
      const mls = await createMlsConversation(currentUser, payload.conversation.id, [contact.id]);
      const chat: Chat = {
        id: payload.conversation.id,
        name: payload.conversation.title,
        initials: payload.conversation.title.split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase(),
        preview: "No messages yet",
        time: "Now",
        color: "green",
        messages: [],
        kind: "direct",
        persisted: true,
        memberIds: [contact.id],
        role: "owner",
      };
      setChats((current) => [chat, ...current]);
      setMlsDeviceId(mls.deviceId);
      setMlsStatuses((current) => ({ ...current, [chat.id]: { ready: true, epoch: mls.epoch, verified: false } }));
      setActiveId(chat.id);
      setDraft("");
      setMobileChatOpen(true);
      setShowNewChat(false);
      setSyncState("online");
      flash("MLS private conversation created");
    } catch (error) {
      flash(error instanceof Error ? error.message : "Conversation could not be created");
    } finally {
      setCreatingChat(false);
    }
  }

  function toggleGroupMember(userId: string) {
    setGroupMemberIds((current) => current.includes(userId) ? current.filter((id) => id !== userId) : [...current, userId]);
  }

  async function createGroupConversation() {
    const title = groupTitle.trim().replace(/\s+/g, " ");
    if (creatingChat || !title || !groupMemberIds.length) return;
    setCreatingChat(true);
    try {
      const response = await fetch("/api/conversations", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ title, kind: "group", memberIds: groupMemberIds }),
      });
      const payload = await readApiResponse<{ conversation?: { id: string; title: string } }>(response);
      if (!response.ok || !payload.conversation) throw new Error(payload.error ?? "Group creation failed");
      const mls = await createMlsConversation(currentUser, payload.conversation.id, groupMemberIds);
      const chat: Chat = {
        id: payload.conversation.id,
        name: payload.conversation.title,
        initials: payload.conversation.title.split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase(),
        preview: `${groupMemberIds.length + 1} members · no messages yet`,
        time: "Now",
        color: "violet",
        messages: [],
        kind: "group",
        persisted: true,
        memberIds: [...groupMemberIds],
        role: "owner",
      };
      setChats((current) => [chat, ...current]);
      setMlsDeviceId(mls.deviceId);
      setMlsStatuses((current) => ({ ...current, [chat.id]: { ready: true, epoch: mls.epoch, verified: false } }));
      setActiveId(chat.id);
      setGroupTitle("");
      setGroupMemberIds([]);
      setDraft("");
      setMobileChatOpen(true);
      setShowNewChat(false);
      setSyncState("online");
      flash("MLS private group created");
    } catch (error) {
      flash(error instanceof Error ? error.message : "Group could not be created");
    } finally {
      setCreatingChat(false);
    }
  }

  async function changeGroupMember(memberId: string, action: "add" | "remove") {
    if (groupAction || activeChat.kind !== "group" || activeChat.role !== "owner") return;
    const person = social.contacts.find((contact) => contact.id === memberId);
    if (!person) return;
    if (action === "remove" && !window.confirm(`Remove ${person.displayName} and rotate the group keys?`)) return;
    setGroupAction(true);
    try {
      const response = await fetch("/api/conversations", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ conversationId: activeChat.id, action, memberId }) });
      const payload = await readApiResponse<{ memberIds?: string[] }>(response);
      if (!response.ok || !payload.memberIds) throw new Error(payload.error ?? "Group membership could not be changed");
      try {
        const epoch = action === "add"
          ? await addMlsGroupMember(currentUser, activeChat.id, memberId)
          : await removeMlsGroupMember(currentUser, activeChat.id, memberId);
        setMlsStatuses((current) => ({ ...current, [activeChat.id]: { ready: true, epoch, verified: false } }));
      } catch (cryptoError) {
        if (action === "add") {
          await fetch("/api/conversations", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ conversationId: activeChat.id, action: "remove", memberId }) });
          throw new Error(cryptoError instanceof Error ? `${cryptoError.message}. Server membership was rolled back.` : "MLS addition failed and server membership was rolled back.");
        }
        setChats((current) => current.map((chat) => chat.id === activeChat.id ? { ...chat, memberIds: payload.memberIds } : chat));
        throw new Error(cryptoError instanceof Error ? `${cryptoError.message}. Server access was removed; reload this device to retry the MLS rekey.` : "Server access was removed, but this device still needs an MLS rekey.");
      }
      setChats((current) => current.map((chat) => chat.id === activeChat.id ? { ...chat, memberIds: payload.memberIds } : chat));
      flash(`${person.displayName} ${action === "add" ? "added" : "removed"} · group keys rotated`);
    } catch (error) {
      flash(error instanceof Error ? error.message : "Group membership could not be changed");
    } finally { setGroupAction(false); }
  }

  async function refreshSocial() {
    const response = await fetch("/api/contacts");
    const payload = await response.json() as Partial<SocialState> & { error?: string };
    if (!response.ok) throw new Error(payload.error ?? "Contacts could not be refreshed");
    setSocial({ contacts: payload.contacts ?? [], incoming: payload.incoming ?? [], outgoing: payload.outgoing ?? [], blocked: payload.blocked ?? [] });
  }

  async function saveProfile(event: FormEvent) {
    event.preventDefault();
    if (socialAction) return;
    setSocialAction(true);
    try {
      const response = await fetch("/api/account", {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ displayName: accountName }),
      });
      const payload = await response.json() as { account?: CurrentUser; error?: string };
      if (!response.ok || !payload.account) throw new Error(payload.error ?? "Profile could not be updated");
      setAccountName(payload.account.displayName);
      flash("Profile updated");
    } catch (error) {
      flash(error instanceof Error ? error.message : "Profile could not be updated");
    } finally {
      setSocialAction(false);
    }
  }

  async function refreshDeviceSecurity() {
    const state = await listAccountDevices(currentUser);
    setDeviceSecurity(state);
    return state;
  }

  async function refreshSessions() {
    const response = await fetch("/api/auth/sessions");
    const payload = await readApiResponse<{ sessions?: ActiveSession[] }>(response);
    if (!response.ok || !payload.sessions) throw new Error(payload.error ?? "Sessions could not be loaded");
    setActiveSessions(payload.sessions);
  }

  async function revokeSessions(action: "one" | "others" | "all", sessionId?: string) {
    const warning = action === "all" ? "Sign out every browser, including this one?" : action === "others" ? "Sign out every other browser?" : "Sign out this browser session?";
    if (!window.confirm(warning)) return;
    setSessionAction(true);
    try {
      const response = await fetch("/api/auth/sessions", { method: "DELETE", headers: { "content-type": "application/json" }, body: JSON.stringify({ action, sessionId }) });
      const payload = await readApiResponse<{ revoked?: number; signedOut?: boolean }>(response);
      if (!response.ok) throw new Error(payload.error ?? "Sessions could not be revoked");
      if (payload.signedOut) { window.location.assign("/"); return; }
      await refreshSessions();
      flash(`${payload.revoked ?? 0} session${payload.revoked === 1 ? "" : "s"} signed out`);
    } catch (error) {
      flash(error instanceof Error ? error.message : "Sessions could not be revoked");
    } finally { setSessionAction(false); }
  }

  function pushApplicationKey(value: string) {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = window.atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  async function setPrivateNotifications(enabled: boolean) {
    if (pushAction || !pushState.supported) return;
    setPushAction(true);
    try {
      if (enabled) {
        const stateResponse = await fetch("/api/push");
        const state = await readApiResponse<{ configured?: boolean; publicKey?: string }>(stateResponse);
        if (!stateResponse.ok || !state.configured || !state.publicKey) throw new Error(state.error ?? "Private notifications are not configured");
        const permission = await Notification.requestPermission();
        if (permission !== "granted") throw new Error(permission === "denied" ? "Notifications are blocked in browser settings" : "Notification permission was not granted");
        const registration = await navigator.serviceWorker.register("/whisper-sw.js", { scope: "/" });
        const existing = await registration.pushManager.getSubscription();
        const subscription = existing ?? await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: pushApplicationKey(state.publicKey) });
        const response = await fetch("/api/push", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(subscription.toJSON()) });
        const payload = await readApiResponse<{ enabled?: boolean }>(response);
        if (!response.ok) throw new Error(payload.error ?? "Private notifications could not be enabled");
        setPushState({ supported: true, configured: true, enabled: true, permission });
        flash("Private notifications enabled on this browser");
      } else {
        const registration = await navigator.serviceWorker.getRegistration("/");
        const subscription = await registration?.pushManager.getSubscription();
        if (subscription) {
          const response = await fetch("/api/push", { method: "DELETE", headers: { "content-type": "application/json" }, body: JSON.stringify({ endpoint: subscription.endpoint }) });
          const payload = await readApiResponse<Record<string, never>>(response);
          if (!response.ok) throw new Error(payload.error ?? "Private notifications could not be disabled");
          await subscription.unsubscribe();
        }
        setPushState((current) => ({ ...current, enabled: false, permission: Notification.permission }));
        flash("Private notifications disabled on this browser");
      }
    } catch (error) {
      flash(error instanceof Error ? error.message : "Notification settings could not be changed");
    } finally { setPushAction(false); }
  }

  async function startLinkingThisBrowser() {
    if (deviceAction) return;
    setDeviceAction(true);
    try {
      const request = await beginDeviceLink(currentUser, `${navigator.platform || "Browser"} · Whisper Web`);
      setLinkRequest({ code: request.code, status: "pending", confirmation: null });
      flash("Link code created. Enter it on a trusted device.");
    } catch (error) {
      flash(error instanceof Error ? error.message : "Device linking could not start");
    } finally {
      setDeviceAction(false);
    }
  }

  async function offerDeviceLink() {
    if (deviceAction || !linkCodeInput.trim()) return;
    setDeviceAction(true);
    try {
      const approval = await acceptDeviceLinkCode(currentUser, linkCodeInput);
      setLinkApproval({ confirmation: approval.confirmation });
      flash("Compare the six groups on both devices before transferring keys");
    } catch (error) {
      flash(error instanceof Error ? error.message : "Link code could not be accepted");
    } finally {
      setDeviceAction(false);
    }
  }

  async function approveDeviceTransfer() {
    if (deviceAction || !linkApproval) return;
    setDeviceAction(true);
    try {
      await confirmDeviceLink(currentUser);
      setLinkApproval(null);
      setLinkCodeInput("");
      flash("Identity transferred securely. Finish linking on the new device.");
    } catch (error) {
      flash(error instanceof Error ? error.message : "Encrypted key transfer failed");
    } finally {
      setDeviceAction(false);
    }
  }

  async function finishDeviceLink() {
    if (deviceAction) return;
    setDeviceAction(true);
    try {
      const linked = await claimDeviceLink(currentUser);
      setMlsDeviceId(linked.deviceId);
      setLinkRequest(null);
      await refreshDeviceSecurity();
      flash("This browser is now a linked Whisper device");
    } catch (error) {
      flash(error instanceof Error ? error.message : "Device linking could not be completed");
    } finally {
      setDeviceAction(false);
    }
  }

  async function backUpAccount() {
    if (deviceAction) return;
    setDeviceAction(true);
    try {
      const backup = await createEncryptedBackup(currentUser);
      setNewRecoveryCode(backup.recoveryCode);
      await refreshDeviceSecurity();
      flash("Encrypted backup updated. Store the recovery key offline.");
    } catch (error) {
      flash(error instanceof Error ? error.message : "Encrypted backup failed");
    } finally {
      setDeviceAction(false);
    }
  }

  async function recoverAccount() {
    if (deviceAction || !recoveryCode.trim()) return;
    setDeviceAction(true);
    try {
      const recovered = await restoreEncryptedBackup(currentUser, recoveryCode);
      setMlsDeviceId(recovered.deviceId);
      setRecoveryCode("");
      await refreshDeviceSecurity();
      flash(`Device recovered with ${recovered.restoredMessages} encrypted history records`);
    } catch (error) {
      flash(error instanceof Error ? error.message : "Account recovery failed");
    } finally {
      setDeviceAction(false);
    }
  }

  async function syncLinkedDevice(deviceId: string) {
    if (deviceAction) return;
    setDeviceAction(true);
    try {
      const result = await provisionDeviceToConversations(currentUser, deviceId);
      flash(`${result.provisioned} chat${result.provisioned === 1 ? "" : "s"} securely added to that device`);
    } catch (error) {
      flash(error instanceof Error ? error.message : "Linked-device chat sync failed");
    } finally {
      setDeviceAction(false);
    }
  }

  async function removeLinkedDevice(deviceId: string) {
    if (deviceAction) return;
    setDeviceAction(true);
    try {
      await revokeDevice(currentUser, deviceId);
      await refreshDeviceSecurity();
      flash("Device removed and MLS memberships rotated");
    } catch (error) {
      flash(error instanceof Error ? error.message : "Device could not be removed");
    } finally {
      setDeviceAction(false);
    }
  }

  async function sendContactInvitation(event: FormEvent) {
    event.preventDefault();
    if (!inviteEmail.trim() || socialAction) return;
    setSocialAction(true);
    try {
      const response = await fetch("/api/contacts", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: inviteEmail }),
      });
      const payload = await response.json() as { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "Invitation could not be sent");
      setInviteEmail("");
      await refreshSocial();
      flash("Contact invitation sent");
    } catch (error) {
      flash(error instanceof Error ? error.message : "Invitation could not be sent");
    } finally {
      setSocialAction(false);
    }
  }

  async function respondToInvitation(invitationId: string, action: "accept" | "decline") {
    if (socialAction) return;
    setSocialAction(true);
    try {
      const response = await fetch("/api/contacts", {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ invitationId, action }),
      });
      const payload = await response.json() as { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "Invitation could not be updated");
      await refreshSocial();
      flash(action === "accept" ? "Contact added" : "Invitation declined");
    } catch (error) {
      flash(error instanceof Error ? error.message : "Invitation could not be updated");
    } finally {
      setSocialAction(false);
    }
  }

  async function setBlocked(userId: string, shouldBlock: boolean) {
    if (socialAction) return;
    if (shouldBlock && !window.confirm("Block this account? You will no longer be able to exchange messages.")) return;
    setSocialAction(true);
    try {
      const response = await fetch("/api/blocks", {
        method: shouldBlock ? "POST" : "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ userId }),
      });
      const payload = await response.json() as { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "Block setting could not be updated");
      await refreshSocial();
      setShowInfo(false);
      flash(shouldBlock ? "Account blocked" : "Account unblocked");
    } catch (error) {
      flash(error instanceof Error ? error.message : "Block setting could not be updated");
    } finally {
      setSocialAction(false);
    }
  }

  async function submitReport(event: FormEvent) {
    event.preventDefault();
    if (!reportTarget || socialAction) return;
    setSocialAction(true);
    try {
      const response = await fetch("/api/reports", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ userId: reportTarget.userId, conversationId: activeChat.persisted ? activeChat.id : null, category: reportCategory, details: reportDetails }),
      });
      const payload = await response.json() as { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "Report could not be submitted");
      setReportTarget(null);
      setReportDetails("");
      setReportCategory("spam");
      flash("Report submitted for review");
    } catch (error) {
      flash(error instanceof Error ? error.message : "Report could not be submitted");
    } finally {
      setSocialAction(false);
    }
  }

  function sendMessage(event: FormEvent) {
    event.preventDefault();
    if (awaitingKeyExchange) {
      flash("Secure contact key exchange is required before messaging");
      return;
    }
    const text = draft.trim();
    if (!text) return;
    if (text.length > MAX_MESSAGE_LENGTH) {
      flash(`Messages can contain up to ${MAX_MESSAGE_LENGTH.toLocaleString()} characters`);
      return;
    }

    if (editingMessage && typeof editingMessage.id === "string") {
      const editing = editingMessage;
      setChats((current) => current.map((chat) => chat.id === activeChat.id ? {
        ...chat,
        messages: chat.messages.map((message) => message.id === editing.id ? { ...message, text, edited: true } : message),
      } : chat));
      setDraft(editing.previousDraft);
      setEditingMessage(null);
      void persistEncryptedControl(activeChat, `[edit]${JSON.stringify({ targetId: editing.id, text })}`).catch(() => {
        setChats((current) => current.map((chat) => chat.id === activeChat.id ? {
          ...chat,
          messages: chat.messages.map((message) => message.id === editing.id ? { ...message, text: editing.originalText, edited: false } : message),
        } : chat));
        flash("Message edit could not be synced securely");
      });
      return;
    }

    const message: Message = {
      id: `local-${crypto.randomUUID()}`,
      text,
      time: formatTime(),
      mine: true,
      status: "sent",
      replyTo: replyingTo?.text,
      replyToId: replyingTo ? String(replyingTo.id) : undefined,
    };

    setChats((current) =>
      current.map((chat) =>
        chat.id === activeChat.id
          ? { ...chat, preview: text, time: message.time, messages: [...chat.messages, message] }
          : chat,
      ),
    );
    setDraft("");
    setReplyingTo(null);
    setShowMediaPicker(false);
    void persistEncryptedMessage(activeChat, message);
  }

  function sendGif(gif: (typeof gifs)[number]) {
    const message: Message = {
      id: `local-${crypto.randomUUID()}`,
      text: gif.label,
      gif: gif.id,
      time: formatTime(),
      mine: true,
      status: "sent",
    };
    setChats((current) => current.map((chat) => chat.id === activeChat.id
      ? { ...chat, preview: `GIF · ${gif.label}`, time: message.time, messages: [...chat.messages, message] }
      : chat));
    setShowMediaPicker(false);
    setGifQuery("");
    void persistEncryptedMessage(activeChat, message);
  }

  function sendOnlineGif(gif: OnlineGif) {
    const message: Message = {
      id: `local-${crypto.randomUUID()}`,
      text: gif.label,
      gif: `tenor-${gif.id}`,
      gifUrl: gif.url,
      gifPreviewUrl: gif.previewUrl,
      time: formatTime(),
      mine: true,
      status: "sent",
    };
    setChats((current) => current.map((chat) => chat.id === activeChat.id
      ? { ...chat, preview: `GIF · ${gif.label}`, time: message.time, messages: [...chat.messages, message] }
      : chat));
    setShowMediaPicker(false);
    setGifQuery("");
    void persistEncryptedMessage(activeChat, message);
  }

  async function uploadEncryptedMedia(file: File, duration?: number) {
    if (mediaUploadState) return;
    if (awaitingKeyExchange) {
      flash("Secure key exchange is required before sharing media");
      return;
    }
    let reservedId: string | null = null;
    try {
      setShowAttachmentMenu(false);
      setMediaUploadState("Validating file…");
      const kind = await validateMediaFile(file);
      const secureChat = await ensurePersistedChat(activeChat);
      const key = createMediaKey();
      setMediaUploadState("Creating encrypted preview…");
      const thumbnail = await createEncryptedThumbnail(file, kind, key);
      setMediaUploadState("Encrypting on this device…");
      const original = await encryptMediaBlob(file, key);

      const reserveResponse = await fetch("/api/attachments", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          conversationId: secureChat.id,
          kind,
          plaintextSize: file.size,
          ciphertextSize: original.ciphertext.size,
          thumbnailCiphertextSize: thumbnail?.ciphertext.size ?? null,
          retention: mediaRetention,
        }),
      });
      const reserved = await reserveResponse.json() as { attachment?: { id: string; expiresAt: string | null }; error?: string };
      if (!reserveResponse.ok || !reserved.attachment) throw new Error(reserved.error ?? "Encrypted upload could not be reserved");
      reservedId = reserved.attachment.id;

      setMediaUploadState("Uploading encrypted media…");
      const uploadPart = async (part: "original" | "thumbnail", ciphertext: Blob) => {
        const response = await fetch(`/api/attachments/${reservedId}?part=${part}`, { method: "PUT", body: ciphertext });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({})) as { error?: string };
          throw new Error(payload.error ?? `Encrypted ${part} upload failed`);
        }
      };
      await uploadPart("original", original.ciphertext);
      if (thumbnail) await uploadPart("thumbnail", thumbnail.ciphertext);
      const finalizeResponse = await fetch("/api/attachments", {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: reservedId }),
      });
      if (!finalizeResponse.ok) {
        const payload = await finalizeResponse.json().catch(() => ({})) as { error?: string };
        throw new Error(payload.error ?? "Encrypted upload could not be finalized");
      }

      const descriptor: AttachmentDescriptor = {
        version: 1,
        id: reservedId,
        kind,
        name: Array.from(file.name).filter((character) => character.charCodeAt(0) >= 32).join("").slice(0, 140) || `${kind}-${reservedId.slice(0, 8)}`,
        mime: file.type,
        size: file.size,
        key: bytesToBase64(key),
        iv: bytesToBase64(original.iv),
        thumbnailIv: thumbnail ? bytesToBase64(thumbnail.iv) : undefined,
        thumbnailMime: thumbnail?.mime,
        retention: mediaRetention,
        expiresAt: reserved.attachment.expiresAt,
        duration,
      };
      const message: Message = {
        id: `local-${crypto.randomUUID()}`,
        text: descriptor.name,
        attachment: descriptor,
        time: formatTime(),
        mine: true,
        status: "sent",
      };
      setChats((current) => current.map((chat) => chat.id === secureChat.id || chat.id === activeChat.id
        ? { ...chat, preview: `${kind === "audio" ? "Voice" : kind.toUpperCase()} · ${descriptor.name}`, time: message.time, messages: [...chat.messages, message] }
        : chat));
      await persistEncryptedMessage(secureChat, message);
      flash(`${kind === "audio" ? "Voice message" : "Media"} encrypted and sent`);
    } catch (cause) {
      if (reservedId) void fetch(`/api/attachments/${reservedId}`, { method: "DELETE" });
      flash(cause instanceof Error ? cause.message : "Media could not be encrypted and uploaded");
    } finally {
      setMediaUploadState(null);
      if (mediaInputRef.current) mediaInputRef.current.value = "";
    }
  }

  async function toggleVoiceRecording() {
    const recorder = mediaRecorderRef.current;
    if (recorder?.state === "recording") {
      recorder.stop();
      return;
    }
    if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === "undefined") {
      flash("Voice recording is not supported by this browser");
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true } });
      const candidates = ["audio/webm;codecs=opus", "audio/mp4", "audio/webm"];
      const recordingMime = candidates.find((type) => MediaRecorder.isTypeSupported(type)) ?? "";
      const nextRecorder = new MediaRecorder(stream, recordingMime ? { mimeType: recordingMime } : undefined);
      mediaStreamRef.current = stream;
      mediaChunksRef.current = [];
      recordingSecondsRef.current = 0;
      setRecordingSeconds(0);
      nextRecorder.ondataavailable = (event) => { if (event.data.size) mediaChunksRef.current.push(event.data); };
      nextRecorder.onstop = () => {
        const baseMime = nextRecorder.mimeType.split(";")[0] || "audio/webm";
        const extension = baseMime === "audio/mp4" ? "m4a" : "webm";
        const voiceFile = new File(mediaChunksRef.current, `Voice message.${extension}`, { type: baseMime });
        stream.getTracks().forEach((track) => track.stop());
        mediaStreamRef.current = null;
        mediaRecorderRef.current = null;
        if (recordingTimerRef.current !== null) window.clearInterval(recordingTimerRef.current);
        recordingTimerRef.current = null;
        setRecordingSeconds(0);
        if (voiceFile.size) void uploadEncryptedMedia(voiceFile, recordingSecondsRef.current);
      };
      mediaRecorderRef.current = nextRecorder;
      nextRecorder.start(500);
      recordingTimerRef.current = window.setInterval(() => {
        recordingSecondsRef.current += 1;
        setRecordingSeconds(recordingSecondsRef.current);
        if (recordingSecondsRef.current >= 300 && nextRecorder.state === "recording") nextRecorder.stop();
      }, 1000);
    } catch (cause) {
      flash(cause instanceof DOMException && cause.name === "NotAllowedError" ? "Microphone permission was denied" : "Voice recording could not start");
    }
  }

  async function persistEncryptedControl(chat: Chat, content: string) {
    const localId = `control-${crypto.randomUUID()}`;
    const usesMls = Boolean(chat.memberIds?.length);
    const encrypted = usesMls ? await encryptMlsMessage(chat.id, content, localId) : await encryptMessage(chat.id, content);
    const response = await fetch("/api/messages", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ conversationId: chat.id, ...encrypted }),
    });
    if (!response.ok) throw new Error("Encrypted control event storage failed");
    if (usesMls) {
      const payload = await readApiResponse<{ message?: { id: string } }>(response);
      if (!payload.message) throw new Error(payload.error ?? "Encrypted control event storage failed");
      await cacheSentMlsMessage(localId, payload.message.id, chat.id);
    }
  }

  async function rotateConversationKeys() {
    if (rotatingKeys || !activeMlsStatus?.ready) return;
    setRotatingKeys(true);
    try {
      const epoch = await rotateMlsEpoch(activeChat.id);
      setMlsStatuses((current) => ({ ...current, [activeChat.id]: { ...(current[activeChat.id] ?? { ready: true, verified: false }), ready: true, epoch } }));
      flash(`Conversation keys rotated to MLS epoch ${epoch}`);
    } catch (error) {
      flash(error instanceof Error ? error.message : "MLS key rotation failed");
    } finally {
      setRotatingKeys(false);
    }
  }

  async function verifySafetyNumber() {
    if (!safetyNumber) return;
    try {
      await markSafetyNumberVerified(activeChat.id, safetyNumber);
      setMlsStatuses((current) => ({ ...current, [activeChat.id]: { ...(current[activeChat.id] ?? { ready: true, epoch: null }), verified: true } }));
      flash("Safety number marked as verified on this device");
    } catch (error) {
      flash(error instanceof Error ? error.message : "Safety number could not be verified");
    }
  }

  function reactToMessage(messageId: Message["id"], reaction: string) {
    const target = activeChat.messages.find((message) => message.id === messageId);
    if (!target) return;
    const active = !target.reactions?.includes(reaction);
    setChats((current) => current.map((chat) => chat.id === activeChat.id ? {
      ...chat,
      messages: chat.messages.map((message) => message.id === messageId
        ? { ...message, reactions: active ? [...(message.reactions ?? []), reaction] : message.reactions?.filter((item) => item !== reaction) }
        : message),
    } : chat));
    setReactionTarget(null);

    if (activeChat.persisted && typeof messageId === "string" && !messageId.startsWith("local-")) {
      void persistEncryptedControl(activeChat, `[reaction]${JSON.stringify({ targetId: messageId, emoji: reaction, active })}`).catch(() => {
        setChats((current) => current.map((chat) => chat.id === activeChat.id ? {
          ...chat,
          messages: chat.messages.map((message) => message.id === messageId
            ? { ...message, reactions: active ? message.reactions?.filter((item) => item !== reaction) : [...(message.reactions ?? []), reaction] }
            : message),
        } : chat));
        flash("Reaction could not be synced securely");
      });
    }
  }

  function startEditingMessage(message: Message) {
    setEditingMessage({ id: message.id, originalText: message.text, previousDraft: draft });
    setDraft(message.text);
    setReplyingTo(null);
    setMessageMenuTarget(null);
  }

  function cancelEditingMessage() {
    if (editingMessage) setDraft(editingMessage.previousDraft);
    setEditingMessage(null);
  }

  function deleteMessage(message: Message) {
    if (typeof message.id !== "string") return;
    const original = message;
    setDeleteTarget(null);
    setMessageMenuTarget(null);
    setChats((current) => current.map((chat) => chat.id === activeChat.id ? {
      ...chat,
      messages: chat.messages.map((entry) => entry.id === message.id
        ? { ...entry, text: "", gif: undefined, gifUrl: undefined, gifPreviewUrl: undefined, attachment: undefined, replyTo: undefined, replyToId: undefined, reactions: [], deleted: true }
        : entry),
    } : chat));
    void persistEncryptedControl(activeChat, `[delete]${JSON.stringify({ targetId: message.id })}`).catch(() => {
      setChats((current) => current.map((chat) => chat.id === activeChat.id ? {
        ...chat,
        messages: chat.messages.map((entry) => entry.id === message.id ? original : entry),
      } : chat));
      flash("Message deletion could not be synced securely");
    });
    if (message.mine && message.attachment) {
      void fetch(`/api/attachments/${encodeURIComponent(message.attachment.id)}`, { method: "DELETE" }).then((response) => {
        if (!response.ok) flash("Message was deleted, but its retained media could not be removed yet");
      });
    }
  }

  async function copyMessage(message: Message) {
    try {
      await navigator.clipboard.writeText(message.text);
      setMessageMenuTarget(null);
      flash("Message copied");
    } catch {
      flash("Could not copy this message");
    }
  }

  function togglePinnedMessage(message: Message) {
    const messageId = String(message.id);
    const storageKey = `whisper-pinned-message:${activeChat.id}`;
    if (pinnedMessageId === messageId) {
      localStorage.removeItem(storageKey);
      setPinnedMessageId(null);
      flash("Message unpinned");
    } else {
      localStorage.setItem(storageKey, messageId);
      setPinnedMessageId(messageId);
      flash("Message pinned");
    }
    setMessageMenuTarget(null);
  }

  function persistChatPreferences(chat: Chat, overrides: Partial<Pick<Chat, "pinned" | "muted" | "archived" | "unread">>) {
    localStorage.setItem(`whisper-chat-preferences:${chat.id}`, JSON.stringify({
      pinned: overrides.pinned ?? Boolean(chat.pinned),
      muted: overrides.muted ?? Boolean(chat.muted),
      archived: overrides.archived ?? Boolean(chat.archived),
      unread: overrides.unread ?? chat.unread ?? 0,
    }));
  }

  function updateChatPreference(preference: "pinned" | "muted" | "archived") {
    const nextValue = !activeChat[preference];
    setChats((current) => current.map((chat) => chat.id === activeChat.id ? { ...chat, [preference]: nextValue } : chat));
    persistChatPreferences(activeChat, { [preference]: nextValue });
    flash(preference === "pinned" ? (nextValue ? "Conversation pinned" : "Conversation unpinned") : preference === "muted" ? (nextValue ? "Notifications muted" : "Notifications enabled") : (nextValue ? "Conversation archived" : "Conversation restored"));
  }

  function markConversationUnread() {
    const unread = Math.max(activeChat.unread ?? 0, 1);
    persistChatPreferences(activeChat, { unread });
    setChats((current) => current.map((chat) => chat.id === activeChat.id ? { ...chat, unread } : chat));
    setShowInfo(false);
    setMobileChatOpen(false);
    setConversationFilter("unread");
    flash("Conversation marked as unread");
  }

  function flash(message: string) {
    setNotice(message);
    window.setTimeout(() => setNotice(null), 2200);
  }

  function retrySecureSync() {
    if (!navigator.onLine) {
      flash("This device is still offline");
      return;
    }
    setSyncState("syncing");
    setSyncRevision((current) => current + 1);
  }

  function toggleTheme() {
    setTheme((current) => {
      const next = current === "light" ? "dark" : "light";
      localStorage.setItem("whisper-theme-v2", next);
      return next;
    });
  }

  function choosePalette(next: ColorPalette) {
    setPalette(next);
    setShowPalette(false);
    localStorage.setItem("whisper-palette-v1", next);
    flash(`${colorPalettes.find((option) => option.id === next)?.name ?? "Color"} palette saved`);
  }

  function toggleCompactMode() {
    setCompactMode((current) => {
      localStorage.setItem("whisper-density", current ? "comfortable" : "compact");
      return !current;
    });
  }

  function toggleReducedMotion() {
    setReducedMotion((current) => {
      localStorage.setItem("whisper-reduced-motion", String(!current));
      return !current;
    });
  }

  function exportConversation() {
    const exportData = {
      conversation: activeChat.name,
      exportedAt: new Date().toISOString(),
      encryptionNotice: "Decrypted locally by the account owner for this export.",
      messages: activeChat.messages.map(({ id, text, time, mine, replyTo, replyToId, reactions, edited, deleted, gifUrl }) => ({ id, text, time, mine: Boolean(mine), replyTo, replyToId, reactions, edited: Boolean(edited), deleted: Boolean(deleted), gifUrl })),
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `whisper-${activeChat.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "conversation"}.json`;
    link.click();
    URL.revokeObjectURL(url);
    flash("Conversation exported on this device");
  }

  return (
    <main className={`app-shell theme-${theme} palette-${palette} ${compactMode ? "compact-mode" : ""} ${reducedMotion ? "reduce-motion" : ""}`}>
      <section className={`sidebar ${mobileChatOpen ? "sidebar-hidden-mobile" : ""}`} aria-label="Conversation list">
        <header className="sidebar-header">
          <button className="avatar avatar-me" aria-label="Open account and contacts" onClick={() => setShowAccount(true)}>{accountName.split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase() || "ME"}</button>
          <div className="brand-lockup">
            <strong>Whisper</strong>
            <button className="sync-status-button" aria-live="polite" onClick={retrySecureSync} disabled={syncState === "syncing"} title={syncState === "offline" ? "Retry secure sync" : undefined}><i className={`status-dot status-${syncState}`} /> {syncState === "online" ? "encrypted · synced" : syncState === "syncing" ? "connecting securely…" : "offline · retry sync"}</button>
          </div>
          <button className="icon-button theme-toggle" aria-pressed={theme === "dark"} aria-label={`Switch to ${theme === "light" ? "dark" : "light"} theme`} onClick={toggleTheme}>{theme === "light" ? "☾" : "☀"}</button>
          <div className="palette-control">
            <button className="icon-button palette-toggle" aria-expanded={showPalette} aria-label="Choose interface color" onClick={() => setShowPalette((value) => !value)}><span /></button>
            {showPalette && <div className="palette-popover" role="dialog" aria-label="Interface color palette">
              <div className="palette-heading"><span><strong>Interface color</strong><small>Saved automatically on this device</small></span><button onClick={() => setShowPalette(false)} aria-label="Close color palette">×</button></div>
              <div className="palette-options">
                {colorPalettes.map((option) => <button key={option.id} className={`palette-option swatch-${option.id}`} aria-pressed={palette === option.id} onClick={() => choosePalette(option.id)}><i /><span><strong>{option.name}</strong><small>{option.note}</small></span>{palette === option.id && <b>✓</b>}</button>)}
              </div>
            </div>}
          </div>
          <button className="icon-button contacts-button" aria-label={`Open contacts${social.incoming.length ? `, ${social.incoming.length} pending invitations` : ""}`} onClick={() => setShowAccount(true)}>♧{social.incoming.length > 0 && <b>{social.incoming.length}</b>}</button>
          <button className="icon-button new-chat" aria-label="Start new chat" onClick={() => setShowNewChat(true)}>＋</button>
        </header>

        <div className="search-wrap">
          <span aria-hidden="true">⌕</span>
          <input ref={searchRef} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search" aria-label="Search conversations" />
          <kbd>⌘ K</kbd>
        </div>

        <nav className="filter-tabs" aria-label="Conversation filters">
          <button aria-pressed={conversationFilter === "all"} className={conversationFilter === "all" ? "active" : ""} onClick={() => setConversationFilter("all")}>All <span>{chats.length}</span></button>
          <button aria-pressed={conversationFilter === "unread"} className={conversationFilter === "unread" ? "active" : ""} onClick={() => setConversationFilter("unread")}>Unread <span>{chats.filter((chat) => Boolean(chat.unread)).length}</span></button>
          <button aria-pressed={conversationFilter === "groups"} className={conversationFilter === "groups" ? "active" : ""} onClick={() => setConversationFilter("groups")}>Groups</button>
          <button aria-pressed={conversationFilter === "saved"} className={conversationFilter === "saved" ? "active" : ""} onClick={() => setConversationFilter("saved")}>Saved</button>
          <button aria-pressed={conversationFilter === "archived"} className={conversationFilter === "archived" ? "active" : ""} onClick={() => setConversationFilter("archived")}>Archived</button>
        </nav>

        <div className="conversation-list">
          {visibleChats.length === 0 ? (
            <div className="empty-list">{query ? `No conversations match “${query}”.` : conversationFilter === "unread" ? "You are all caught up." : conversationFilter === "groups" ? "No group conversations yet." : conversationFilter === "archived" ? "No archived conversations." : "No saved conversations yet."}</div>
          ) : visibleChats.map((chat) => (
            <button
              key={chat.id}
              aria-current={chat.id === activeId ? "page" : undefined}
              className={`conversation ${chat.id === activeId ? "active" : ""}`}
              onClick={() => selectChat(chat.id)}
            >
              <span className={`avatar avatar-${chat.color}`}>{chat.initials}{chat.online && <i className="online-dot" />}</span>
              <span className="conversation-copy">
                <span className="conversation-title"><strong>{chat.name}</strong><time>{chat.time}</time></span>
                <span className="conversation-preview">
                  <span>{chat.preview}</span>
                  <span className="conversation-badges">
                    {chat.pinned && <b title="Pinned">◆</b>}
                    {chat.muted && <b title="Muted">×</b>}
                    {!!chat.unread && <em>{chat.unread}</em>}
                  </span>
                </span>
              </span>
            </button>
          ))}
        </div>

        <footer className="privacy-footer"><span>⌁</span> End-to-end encrypted <a href="/security">Security</a><a href="/privacy">Privacy</a><a href="/terms">Terms</a><button onClick={() => setShowShortcutHelp(true)} aria-label="Show keyboard shortcuts">⌘ /</button></footer>
      </section>

      <section className={`chat-panel ${mobileChatOpen ? "chat-open-mobile" : ""}`} aria-label={`Chat with ${activeChat.name}`}>
        <header className="chat-header">
          <button className="icon-button back-button" aria-label="Back to chats" onClick={() => setMobileChatOpen(false)}>‹</button>
          <button className={`avatar avatar-${activeChat.color}`} aria-label={`Open ${activeChat.name} details`} onClick={() => setShowInfo(true)}>{activeChat.initials}</button>
          <button className="chat-identity" onClick={() => setShowInfo(true)}>
            <strong>{activeChat.name}</strong>
            <span>{activeChat.online ? "online now" : "last seen recently"}</span>
          </button>
          <div className="chat-actions">
            <button className={`icon-button ${showChatSearch ? "active" : ""}`} aria-label="Search chat" onClick={() => showChatSearch ? setShowChatSearch(false) : openChatSearch()}>⌕</button>
            <button className="icon-button" aria-label="Encrypted calls are not available yet" title="Encrypted calls are not available yet" disabled>♢</button>
            <button className="icon-button" aria-label="More options" onClick={() => setShowInfo((value) => !value)}>•••</button>
          </div>
        </header>

        {showChatSearch && (
          <div className="chat-search-panel" role="search">
            <div className="chat-search-field">
              <span aria-hidden="true">⌕</span>
              <input ref={chatSearchRef} value={chatSearchQuery} onChange={(event) => setChatSearchQuery(event.target.value)} placeholder={`Search in ${activeChat.name}`} aria-label={`Search messages in ${activeChat.name}`} />
              {chatSearchQuery && <button onClick={() => setChatSearchQuery("")} aria-label="Clear chat search">×</button>}
              <button onClick={() => setShowChatSearch(false)} aria-label="Close chat search">Done</button>
            </div>
            {chatSearchQuery.trim() && (
              <div className="chat-search-results" aria-live="polite">
                {chatSearchResults.length ? chatSearchResults.map((message) => (
                  <button key={message.id} onClick={() => focusMessage(message.id)}>
                    <span>{message.mine ? "You" : activeChat.name}</span>
                    <strong>{message.text}</strong>
                    <time>{message.time}</time>
                  </button>
                )) : <p>No matching messages</p>}
              </div>
            )}
          </div>
        )}

        {pinnedMessage && (
          <div className="pinned-message-banner" aria-label="Pinned message">
            <button className="pinned-message-jump" onClick={() => focusMessage(pinnedMessage.id)}>
              <span aria-hidden="true">◆</span>
              <span><strong>Pinned message</strong><small>{pinnedMessage.text || "GIF"}</small></span>
            </button>
            <button className="pinned-message-close" onClick={() => togglePinnedMessage(pinnedMessage)} aria-label="Unpin message">×</button>
          </div>
        )}

        <div className="encryption-banner">
          <span>⌁</span>
          <p>{activeChat.memberIds?.length
            ? activeMlsStatus?.ready
              ? <><strong>MLS end-to-end encryption active.</strong> RFC 9420 · epoch {activeMlsStatus.epoch} · {activeMlsStatus.verified ? "safety number verified" : "verification recommended"}.</>
              : <><strong>Authenticated key exchange pending.</strong> Messaging unlocks when this device receives or creates an MLS session.</>
            : <><strong>Encrypted private notes.</strong> The key stays in this browser.</>}</p>
        </div>

        <div className="message-space" ref={messageSpaceRef} onScroll={handleMessageScroll}>
          <div className="day-divider"><span>Today</span></div>
          <div className="messages" aria-live="polite">
            {activeChat.messages.length === 0 && (
              <section className="classified-empty" aria-label="Secure channel ready">
                <div className="classified-orbit" aria-hidden="true"><span>⌁</span></div>
                <p>WHISPER / EYES ONLY</p>
                <h2>{activeChat.kind === "saved" ? "Your private vault is ready" : "Secure channel established"}</h2>
                <span>{activeChat.kind === "saved" ? "Write a note only this device can unlock." : "Send the first end-to-end encrypted signal."}</span>
                <div><b>AES-256</b><b>LOCAL KEY</b><b>NO TRACE</b></div>
              </section>
            )}
            {activeChat.messages.map((message) => (
              <div
                key={message.id}
                ref={(element) => { if (element) messageRefs.current.set(String(message.id), element); else messageRefs.current.delete(String(message.id)); }}
                className={`message-row ${message.mine ? "mine" : "theirs"} ${highlightedMessageId === message.id ? "search-highlight" : ""}`}
              >
                {!message.mine && <span className={`mini-avatar avatar-${activeChat.color}`}>{activeChat.initials}</span>}
                <div className="bubble">
                  {message.deleted ? <p className="deleted-message">Message deleted</p> : <>
                  {message.replyTo && (message.replyToId
                    ? <button className="reply-quote" onClick={() => focusMessage(message.replyToId!)} aria-label="Jump to replied message">{message.replyTo}</button>
                    : <div className="reply-quote">{message.replyTo}</div>)}
                  {message.attachment ? <EncryptedAttachment attachment={message.attachment} /> : message.gifUrl ? (
                    <div className="online-gif-message">
                      <Image src={message.gifUrl} alt={message.text} width={640} height={480} unoptimized />
                      <span className="online-gif-label">{message.text}</span>
                      <i>GIF · TENOR</i>
                    </div>
                  ) : message.gif ? (() => {
                    const gif = gifs.find((item) => item.id === message.gif) ?? gifs[0];
                    return <div className={`gif-message gif-${gif.id}`} style={{ "--gif-a": gif.colors[0], "--gif-b": gif.colors[1] } as CSSProperties}><span>{gif.emoji}</span><strong>{gif.label}</strong><i>GIF</i></div>;
                  })() : <MessageText text={message.text} />}
                  </>}
                  <span className="message-meta">
                    {message.edited && !message.deleted && <i>edited</i>}
                    {message.time}
                    {message.mine && (message.status === "failed" ? (
                      <button className="retry-message" aria-label="Retry sending message" title="Retry" onClick={() => void persistEncryptedMessage(activeChat, message)}>!</button>
                    ) : <b aria-label={message.status === "read" ? "Read" : "Sent"}>{message.status === "read" ? "✓✓" : "✓"}</b>)}
                  </span>
                  {!message.deleted && <button className="add-reaction" aria-label="React to message" onClick={() => setReactionTarget(reactionTarget === message.id ? null : message.id)}>☺</button>}
                  {!message.deleted && <button className="reply-message" aria-label="Reply to message" onClick={() => { setReplyingTo({ id: message.id, text: message.text }); setReactionTarget(null); }}>↩</button>}
                  {!message.deleted && (
                    <>
                      <button className="message-more" aria-label="Message options" onClick={() => setMessageMenuTarget(messageMenuTarget === message.id ? null : message.id)}>•••</button>
                      {messageMenuTarget === message.id && <div className="message-action-menu">
                        <button onClick={() => void copyMessage(message)}>Copy message</button>
                        <button onClick={() => togglePinnedMessage(message)}>{pinnedMessageId === String(message.id) ? "Unpin message" : "Pin message"}</button>
                        {message.mine && activeChat.persisted && typeof message.id === "string" && !message.id.startsWith("local-") && <>
                          {!message.gif && !message.gifUrl && !message.attachment && <button onClick={() => startEditingMessage(message)}>Edit message</button>}
                          <button className="danger" onClick={() => { setDeleteTarget(message); setMessageMenuTarget(null); }}>Delete message</button>
                        </>}
                      </div>}
                    </>
                  )}
                  {reactionTarget === message.id && !message.deleted && (
                    <div className="reaction-picker">
                      {["❤️", "😂", "😮", "😢", "🔥", "👍", "👎", "🎉"].map((reaction) => <button key={reaction} onClick={() => reactToMessage(message.id, reaction)}>{reaction}</button>)}
                    </div>
                  )}
                  {!message.deleted && !!message.reactions?.length && <div className="message-reactions">{message.reactions.map((reaction) => <button key={reaction} onClick={() => reactToMessage(message.id, reaction)}>{reaction} <span>1</span></button>)}</div>}
                </div>
              </div>
            ))}
          </div>
          {showScrollLatest && <button className="scroll-latest" onClick={scrollToLatest} aria-label="Scroll to latest message">↓ Newest</button>}
        </div>

        <div className="composer-zone">
          {awaitingKeyExchange && <div className="key-exchange-notice"><strong>Waiting for MLS keys</strong><span>{mlsError[activeChat.id] || "Ask your contact to open Whisper once so their authenticated device key can be published."}</span></div>}
          {mediaUploadState && <div className="media-upload-status" role="status"><span className="media-upload-spinner" /> <strong>{mediaUploadState}</strong><small>Only ciphertext leaves this device</small></div>}
          {recordingSeconds > 0 && <div className="voice-recording-status" role="status"><span /> <strong>Recording voice message</strong><time>{Math.floor(recordingSeconds / 60)}:{String(recordingSeconds % 60).padStart(2, "0")}</time><button onClick={() => void toggleVoiceRecording()}>Stop &amp; encrypt</button></div>}
          {showAttachmentMenu && (
            <div className="attachment-menu" aria-label="Encrypted media options">
              <div><strong>Send encrypted media</strong><small>Images, GIFs, video, audio, documents, and archives</small></div>
              <button type="button" onClick={() => mediaInputRef.current?.click()}><span>＋</span>Choose file</button>
              <label>Delete from storage
                <select value={mediaRetention} onChange={(event) => setMediaRetention(event.target.value as MediaRetention)}>
                  <option value="1d">After 1 day</option><option value="7d">After 7 days</option><option value="30d">After 30 days</option><option value="forever">Only when I delete it</option>
                </select>
              </label>
              <p>Files and previews are encrypted with a fresh AES-256 key before upload. The key is shared only inside the end-to-end encrypted message.</p>
            </div>
          )}
          {showMediaPicker && (
            <div className="media-picker" aria-label="Emoji and GIF picker">
              <div className="picker-tabs">
                <button className={pickerTab === "emoji" ? "active" : ""} onClick={() => setPickerTab("emoji")}>Emoji</button>
                <button className={pickerTab === "gif" ? "active" : ""} onClick={() => setPickerTab("gif")}>GIFs</button>
                <button className="picker-close" onClick={() => setShowMediaPicker(false)} aria-label="Close picker">×</button>
              </div>
              {pickerTab === "emoji" ? (
                <>
                  <div className="emoji-categories">{emojiGroups.map((group) => <button key={group.name} className={emojiGroup === group.name ? "active" : ""} title={group.name} onClick={() => setEmojiGroup(group.name)}>{group.icon}</button>)}</div>
                  <p className="picker-label">{emojiGroup}</p>
                  <div className="emoji-grid">{emojiGroups.find((group) => group.name === emojiGroup)?.emojis.map((emoji) => <button key={emoji} onClick={() => setDraft((value) => value + emoji)}>{emoji}</button>)}</div>
                </>
              ) : (
                <>
                  <div className="gif-search"><span>⌕</span><input value={gifQuery} onChange={(event) => setGifQuery(event.target.value)} placeholder="Search Tenor and Whisper GIFs" aria-label="Search GIFs online" />{gifSearchState === "loading" && <i className="gif-search-spinner" aria-label="Searching" />}</div>
                  <div className="gif-source-heading"><strong>{gifQuery.trim() ? "Online results" : "Trending online"}</strong><span>powered by Tenor</span></div>
                  {gifSearchState === "unconfigured" && <div className="gif-online-note"><strong>Online search is ready to connect</strong><span>Add a Tenor API key to search the web. Your current Whisper GIFs remain below.</span></div>}
                  {gifSearchState === "error" && <div className="gif-online-note error"><strong>Couldn’t reach online GIFs</strong><span>Showing the built-in collection instead.</span></div>}
                  {gifSearchState === "ready" && onlineGifs.length === 0 && <div className="gif-online-note"><strong>No online matches</strong><span>Try another phrase or choose a Whisper GIF.</span></div>}
                  {!!onlineGifs.length && <div className="online-gif-grid">{onlineGifs.map((gif) => <button key={gif.id} onClick={() => sendOnlineGif(gif)} className="online-gif-card" title={`Send ${gif.label}`}><Image src={gif.previewUrl} alt={gif.label} width={gif.width} height={gif.height} unoptimized /><span>{gif.label}</span><i>GIF</i></button>)}</div>}
                  <div className="gif-source-heading built-in"><strong>Whisper GIFs</strong><span>always available</span></div>
                  <div className="gif-grid">{gifs.filter((gif) => gif.label.toLowerCase().includes(gifQuery.toLowerCase())).map((gif) => <button key={gif.id} onClick={() => sendGif(gif)} className={`gif-card gif-${gif.id}`} style={{ "--gif-a": gif.colors[0], "--gif-b": gif.colors[1] } as CSSProperties}><span>{gif.emoji}</span><strong>{gif.label}</strong><i>GIF</i></button>)}</div>
                </>
              )}
            </div>
          )}
          <input ref={mediaInputRef} className="visually-hidden media-file-input" type="file" accept="image/jpeg,image/png,image/webp,image/gif,video/mp4,video/webm,video/quicktime,audio/webm,audio/ogg,audio/mpeg,audio/wav,audio/mp4,.pdf,.zip,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.csv,.json" onChange={(event) => { const file = event.target.files?.[0]; if (file) void uploadEncryptedMedia(file); }} />
          {replyingTo && (
            <div className="reply-composer" role="status">
              <span>Replying to</span>
              <strong>{replyingTo.text}</strong>
              <button onClick={() => setReplyingTo(null)} aria-label="Cancel reply">×</button>
            </div>
          )}
          {editingMessage && (
            <div className="reply-composer edit-composer" role="status">
              <span>Editing message</span>
              <strong>{editingMessage.originalText}</strong>
              <button onClick={cancelEditingMessage} aria-label="Cancel editing">×</button>
            </div>
          )}
          <form className="composer" onSubmit={sendMessage}>
            <button type="button" className={`composer-button ${showAttachmentMenu ? "active" : ""}`} aria-label="Add encrypted attachment" title="Add encrypted attachment" onClick={() => { setShowAttachmentMenu((value) => !value); setShowMediaPicker(false); }} disabled={awaitingKeyExchange || Boolean(mediaUploadState)}>⌇</button>
            <input maxLength={MAX_MESSAGE_LENGTH} value={draft} onChange={(event) => setDraft(event.target.value)} placeholder={awaitingKeyExchange ? "Secure key exchange required" : "Write a message…"} aria-label="Message" disabled={awaitingKeyExchange} />
            <button type="button" className={`composer-button ${showMediaPicker ? "active" : ""}`} aria-label="Add emoji or GIF" onClick={() => setShowMediaPicker((value) => !value)} disabled={awaitingKeyExchange}>☺</button>
            <button type={draft.trim() ? "submit" : "button"} className={`send-button ${draft.trim() && !awaitingKeyExchange ? "ready" : ""} ${recordingSeconds ? "recording" : ""}`} aria-label={awaitingKeyExchange ? "Secure key exchange required" : draft.trim() ? "Send message" : recordingSeconds ? "Stop and send encrypted voice message" : "Record encrypted voice message"} onClick={() => !draft.trim() && !awaitingKeyExchange && void toggleVoiceRecording()} disabled={awaitingKeyExchange || Boolean(mediaUploadState)}>
              {draft.trim() ? "➤" : recordingSeconds ? "■" : "♩"}
            </button>
          </form>
          <p className="composer-hint">{draft.length >= MAX_MESSAGE_LENGTH * .8 ? `${draft.length.toLocaleString()} / ${MAX_MESSAGE_LENGTH.toLocaleString()} · ` : draft ? "Draft saved on this device · " : "Attach files or tap the note to record · "}<span>{activeMlsStatus?.ready ? `MLS epoch ${activeMlsStatus.epoch}` : "encrypted on this device"}</span></p>
        </div>
      </section>

      {showInfo && (
        <aside className="info-panel" aria-label="Conversation details">
          <button className="close-info" onClick={() => setShowInfo(false)} aria-label="Close details">×</button>
          <span className={`avatar info-avatar avatar-${activeChat.color}`}>{activeChat.initials}</span>
          <h2>{activeChat.name}</h2>
          <p className="info-status">{activeChat.online ? "online" : "last seen recently"}</p>
          <div className="quick-actions">
            <button aria-pressed={Boolean(activeChat.muted)} onClick={() => updateChatPreference("muted")}><span>{activeChat.muted ? "♪" : "♩"}</span>{activeChat.muted ? "Unmute" : "Mute"}</button>
            <button aria-pressed={Boolean(activeChat.pinned)} onClick={() => updateChatPreference("pinned")}><span>◆</span>{activeChat.pinned ? "Unpin" : "Pin"}</button>
            <button disabled title="Encrypted calls are not available yet"><span>♢</span>Call</button>
            <button onClick={openChatSearch}><span>⌕</span>Search</button>
          </div>
          <div className="info-card">
            <div><span>Encryption</span><strong>{activeMlsStatus?.ready ? `MLS epoch ${activeMlsStatus.epoch}` : "Device key active"}</strong></div>
            <p>{activeMlsStatus?.ready ? activeChat.kind === "group" ? "RFC 9420 MLS provides forward secrecy and epoch-based key rotation for every current group member." : "RFC 9420 MLS provides forward secrecy and epoch-based key rotation. Verify the safety number with your contact over another channel." : "Private-note keys are stored only in this browser."}</p>
            {safetyNumber && <div className="safety-number" aria-label="Conversation safety number">{safetyNumber}</div>}
            {activeMlsStatus?.ready && <div className="security-actions">
              <button onClick={() => void navigator.clipboard.writeText(safetyNumber ?? "").then(() => flash("Safety number copied"))} disabled={!safetyNumber}>Copy number</button>
              <button onClick={() => void verifySafetyNumber()} disabled={!safetyNumber || activeMlsStatus.verified}>{activeMlsStatus.verified ? "Verified" : "Mark verified"}</button>
              <button onClick={() => void rotateConversationKeys()} disabled={rotatingKeys}>{rotatingKeys ? "Rotating…" : "Rotate keys"}</button>
            </div>}
          </div>
          {activeChat.kind === "group" && <section className="group-management" aria-labelledby="group-members-title">
            <div className="social-title"><h3 id="group-members-title">Members</h3><span>{(activeChat.memberIds?.length ?? 0) + 1}</span></div>
            <div className="group-member-list">
              <div><span className="person-avatar">{accountName.slice(0, 2).toUpperCase()}</span><span><strong>{accountName}</strong><small>{activeChat.role === "owner" ? "Owner · you" : "You"}</small></span></div>
              {(activeChat.memberIds ?? []).map((memberId) => {
                const person = social.contacts.find((contact) => contact.id === memberId);
                return <div key={memberId}><span className="person-avatar">{person?.displayName.slice(0, 2).toUpperCase() ?? "••"}</span><span><strong>{person?.displayName ?? "Group member"}</strong><small>{person?.email ?? `Encrypted member · ${memberId.slice(-8)}`}</small></span>{activeChat.role === "owner" && person && <button disabled={groupAction} onClick={() => void changeGroupMember(memberId, "remove")}>Remove</button>}</div>;
              })}
            </div>
            {activeChat.role === "owner" && <div className="group-add-list"><strong>Add accepted contact</strong>{social.contacts.filter((contact) => !activeChat.memberIds?.includes(contact.id)).map((contact) => <button key={contact.id} disabled={groupAction} onClick={() => void changeGroupMember(contact.id, "add")}><span>{contact.displayName}</span><b>+</b></button>)}{!social.contacts.some((contact) => !activeChat.memberIds?.includes(contact.id)) && <small>Every accepted contact is already a member.</small>}</div>}
          </section>}
          <button className="archive-chat-action" onClick={() => updateChatPreference("archived")}>{activeChat.archived ? "Restore conversation" : "Archive conversation"}</button>
          <button className="archive-chat-action export-chat-action" onClick={exportConversation}>Export conversation</button>
          {activeChat.kind === "direct" && !!activeChat.memberIds?.[0] && <div className="trust-actions">
            <button onClick={() => void setBlocked(activeChat.memberIds![0], true)}>Block account</button>
            <button onClick={() => setReportTarget({ userId: activeChat.memberIds![0], name: activeChat.name })}>Report account</button>
          </div>}
          <div className="preference-actions">
            <button onClick={markConversationUnread}><span>Conversation</span><strong>Mark unread</strong></button>
            <button aria-pressed={compactMode} onClick={toggleCompactMode}><span>Density</span><strong>{compactMode ? "Compact" : "Comfortable"}</strong></button>
            <button aria-pressed={reducedMotion} onClick={toggleReducedMotion}><span>Motion</span><strong>{reducedMotion ? "Reduced" : "Full"}</strong></button>
          </div>
          <div className="media-row"><strong>Shared media</strong><button onClick={() => flash("All shared media")}>View all</button></div>
          <div className="media-grid"><span>Lisbon</span><span>Notes</span><span>4 files</span></div>
        </aside>
      )}

      {showNewChat && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && setShowNewChat(false)}>
          <section className="new-chat-modal" role="dialog" aria-modal="true" aria-labelledby="new-chat-title">
            <button className="modal-close" onClick={() => setShowNewChat(false)} aria-label="Close new conversation">×</button>
            <span className="modal-icon">⌁</span>
            <h2 id="new-chat-title">Start a private conversation</h2>
            <p>Choose accepted contacts. Whisper enforces membership and creates a fresh MLS group for the selected accounts.</p>
            <div className="new-chat-tabs" role="tablist" aria-label="Conversation type"><button role="tab" aria-selected={newChatMode === "direct"} onClick={() => setNewChatMode("direct")}>Direct</button><button role="tab" aria-selected={newChatMode === "group"} onClick={() => setNewChatMode("group")}>Group</button></div>
            {newChatMode === "group" && <label className="group-name-field" htmlFor="group-name">Group name<input id="group-name" maxLength={80} value={groupTitle} onChange={(event) => setGroupTitle(event.target.value)} placeholder="Operation name" /></label>}
            <div className="people-list compact-people-list">
              {social.contacts.length ? social.contacts.map((contact) => newChatMode === "direct" ? (
                <button key={contact.id} className="person-row" onClick={() => void createConversation(contact)} disabled={creatingChat}>
                  <span className="person-avatar">{contact.displayName.slice(0, 2).toUpperCase()}</span>
                  <span><strong>{contact.displayName}</strong><small>{contact.email}</small></span>
                  <b>{creatingChat ? "…" : "Chat"}</b>
                </button>
              ) : <button key={contact.id} className={`person-row group-person-row ${groupMemberIds.includes(contact.id) ? "selected" : ""}`} aria-pressed={groupMemberIds.includes(contact.id)} onClick={() => toggleGroupMember(contact.id)} disabled={creatingChat}>
                <span className="person-avatar">{contact.displayName.slice(0, 2).toUpperCase()}</span>
                <span><strong>{contact.displayName}</strong><small>{contact.email}</small></span>
                <b>{groupMemberIds.includes(contact.id) ? "✓" : "+"}</b>
              </button>) : <div className="social-empty"><strong>No accepted contacts yet</strong><span>Open your account panel and invite someone by email first.</span></div>}
            </div>
            {newChatMode === "group" && <p className="group-selection-count">{groupMemberIds.length} contact{groupMemberIds.length === 1 ? "" : "s"} selected</p>}
            <div className="modal-actions"><button type="button" onClick={() => setShowNewChat(false)}>Close</button><button className="primary" type="button" onClick={() => { setShowNewChat(false); setShowAccount(true); }}>Manage contacts</button></div>
            {newChatMode === "group" && <button className="create-group-action" type="button" disabled={creatingChat || !groupTitle.trim() || !groupMemberIds.length} onClick={() => void createGroupConversation()}>{creatingChat ? "Securing group…" : "Create encrypted group"}</button>}
          </section>
        </div>
      )}

      {showAccount && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && setShowAccount(false)}>
          <section className="new-chat-modal account-modal" role="dialog" aria-modal="true" aria-labelledby="account-title">
            <button className="modal-close" onClick={() => setShowAccount(false)} aria-label="Close account and contacts">×</button>
            <div className="account-heading"><span className="avatar avatar-me">{accountName.slice(0, 2).toUpperCase()}</span><span><p>Signed in as</p><h2 id="account-title">{accountName}</h2><small>{currentUser.email}</small></span></div>
            <form className="profile-form" onSubmit={saveProfile}>
              <label htmlFor="profile-name">Display name</label>
              <div><input id="profile-name" maxLength={60} value={accountName} onChange={(event) => setAccountName(event.target.value)} /><button type="submit" disabled={socialAction || accountName.trim().length < 2}>Save</button></div>
            </form>
            <section className="session-security-section" aria-labelledby="session-security-title">
              <div className="social-title"><h3 id="session-security-title">Signed-in browsers</h3><span>{activeSessions.length}</span></div>
              <p className="session-explanation">Review account sessions separately from encrypted-device keys. Revoking a browser removes its account access immediately.</p>
              <div className="session-list">
                {activeSessions.map((session) => <div className="session-row" key={session.id}>
                  <span className="session-symbol">{session.current ? "●" : "○"}</span>
                  <span><strong>{session.current ? "This browser" : "Signed-in browser"}</strong><small>Seen {new Date(session.lastSeenAt).toLocaleString()} · ID {session.fingerprint}</small></span>
                  {!session.current && <button type="button" disabled={sessionAction} onClick={() => void revokeSessions("one", session.id)}>Sign out</button>}
                </div>)}
                {!activeSessions.length && <p className="social-loading">Loading active sessions…</p>}
              </div>
              {activeSessions.length > 1 && <div className="session-bulk-actions"><button type="button" disabled={sessionAction} onClick={() => void revokeSessions("others")}>Sign out other browsers</button><button className="danger-text" type="button" disabled={sessionAction} onClick={() => void revokeSessions("all")}>Sign out everywhere</button></div>}
            </section>
            <section className="notification-security-section" aria-labelledby="notification-security-title">
              <div className="social-title"><h3 id="notification-security-title">Private notifications</h3><span>{pushState.enabled ? "On" : "Off"}</span></div>
              <div className="notification-control">
                <span><strong>Generic alerts on this browser</strong><small>Alerts say only “New encrypted message.” Message text, sender names, chat names, and encryption keys never enter the notification payload.</small></span>
                <button type="button" aria-pressed={pushState.enabled} disabled={pushAction || !pushState.supported || !pushState.configured || pushState.permission === "denied"} onClick={() => void setPrivateNotifications(!pushState.enabled)}>{pushAction ? "Working…" : pushState.enabled ? "Disable" : "Enable"}</button>
              </div>
              {!pushState.supported && <p className="notification-note">This browser does not support Web Push.</p>}
              {pushState.supported && !pushState.configured && <p className="notification-note">Add VAPID keys to the deployment to make this opt-in available.</p>}
              {pushState.permission === "denied" && <p className="notification-note warning">Notifications are blocked. Allow them in this site’s browser settings first.</p>}
            </section>
            <section className="device-security-section" aria-labelledby="device-security-title">
              <div className="social-title"><h3 id="device-security-title">Devices & recovery</h3><span>{deviceSecurity?.devices.length ?? 0}</span></div>
              {!deviceSecurity ? <p className="social-loading">Loading encrypted devices…</p> : <>
                <div className="device-list">
                  {deviceSecurity.devices.map((device) => <div className="device-row" key={device.id}>
                    <span className="device-symbol">{device.current ? "●" : "○"}</span>
                    <span><strong>{device.name}</strong><small>{device.current ? "This browser" : `Active · ${device.updatedAt ? new Date(device.updatedAt).toLocaleDateString() : "linked"}`}</small></span>
                    {!device.current && deviceSecurity.localDeviceId && <span className="device-actions"><button disabled={deviceAction} onClick={() => void syncLinkedDevice(device.id)}>Sync chats</button><button className="danger-text" disabled={deviceAction} onClick={() => void removeLinkedDevice(device.id)}>Remove</button></span>}
                  </div>)}
                </div>
                {!deviceSecurity.localDeviceId && <div className="device-callout warning"><strong>This browser is not linked</strong><span>Use a trusted device or your recovery key. A new identity will not silently replace your existing account.</span><button disabled={deviceAction || Boolean(linkRequest)} onClick={() => void startLinkingThisBrowser()}>Create link code</button></div>}
                {linkRequest && <div className="device-callout link-code-card"><strong>Enter this code on a trusted device</strong><code>{linkRequest.code}</code><span>Status: {linkRequest.status}{linkRequest.confirmation ? " · compare the authentication code below" : ""}</span>{linkRequest.confirmation && <b className="link-confirmation">{linkRequest.confirmation}</b>}{linkRequest.status === "ready" && <button disabled={deviceAction} onClick={() => void finishDeviceLink()}>Finish linking this browser</button>}</div>}
                {deviceSecurity.canApproveLinks && <div className="device-callout"><strong>Link another browser</strong><span>Enter the high-entropy code shown there. Compare all six authentication groups before approval. A legacy 0.5 identity is securely rotated the first time recovery is enabled, which changes contact safety numbers.</span><div className="inline-security-form"><input value={linkCodeInput} onChange={(event) => setLinkCodeInput(event.target.value)} placeholder="Device link code" aria-label="Device link code" /><button disabled={deviceAction || !linkCodeInput.trim()} onClick={() => void offerDeviceLink()}>Continue</button></div>{linkApproval && <div className="confirmation-check"><span>Authentication code</span><b>{linkApproval.confirmation}</b><button disabled={deviceAction} onClick={() => void approveDeviceTransfer()}>Codes match — transfer keys</button></div>}</div>}
                <div className="device-callout backup-card"><strong>Encrypted recovery backup</strong><span>{deviceSecurity.backupUpdatedAt ? `Last updated ${new Date(deviceSecurity.backupUpdatedAt).toLocaleString()}. ` : "No backup yet. "}Only someone with your 256-bit recovery key can decrypt it.</span>{deviceSecurity.localDeviceId && <button disabled={deviceAction} onClick={() => void backUpAccount()}>{deviceSecurity.backupUpdatedAt ? "Update backup" : "Create backup"}</button>}{newRecoveryCode && <div className="recovery-key"><span>Store this key offline</span><code>{newRecoveryCode}</code><button onClick={() => void navigator.clipboard.writeText(newRecoveryCode).then(() => flash("Recovery key copied"))}>Copy recovery key</button></div>}</div>
                {!deviceSecurity.localDeviceId && deviceSecurity.backupUpdatedAt && <div className="device-callout recovery-card"><strong>Recover a lost device</strong><span>Recovery replaces other active devices and restores encrypted cached history. Contacts must add this new device back to active MLS chats.</span><div className="inline-security-form"><input value={recoveryCode} onChange={(event) => setRecoveryCode(event.target.value)} placeholder="Recovery key" aria-label="Recovery key" /><button disabled={deviceAction || !recoveryCode.trim()} onClick={() => void recoverAccount()}>Recover</button></div></div>}
              </>}
            </section>
            <section className="social-section">
              <div className="social-title"><h3>Contacts</h3><span>{social.contacts.length}</span></div>
              <form className="invite-form" onSubmit={sendContactInvitation}><input type="email" maxLength={254} value={inviteEmail} onChange={(event) => setInviteEmail(event.target.value)} placeholder="Invite by registered email" aria-label="Contact email" /><button disabled={socialAction || !inviteEmail.trim()}>Invite</button></form>
              {socialLoading ? <p className="social-loading">Loading your trusted network…</p> : <div className="people-list">
                {social.incoming.map((invitation) => <div className="person-row invitation-row" key={invitation.id}><span className="person-avatar">{invitation.person.displayName.slice(0, 2).toUpperCase()}</span><span><strong>{invitation.person.displayName}</strong><small>wants to connect</small></span><span className="invitation-actions"><button onClick={() => void respondToInvitation(invitation.id, "decline")}>Decline</button><button className="accept" onClick={() => void respondToInvitation(invitation.id, "accept")}>Accept</button></span></div>)}
                {social.contacts.map((contact) => <div className="person-row" key={contact.id}><span className="person-avatar">{contact.displayName.slice(0, 2).toUpperCase()}</span><span><strong>{contact.displayName}</strong><small>{contact.email}</small></span><span className="person-actions"><button onClick={() => { setShowAccount(false); setShowNewChat(true); }}>Message</button><button className="danger-text" onClick={() => void setBlocked(contact.id, true)}>Block</button></span></div>)}
                {!social.contacts.length && !social.incoming.length && <div className="social-empty"><strong>Your contacts will appear here</strong><span>The other person must sign in once before an invitation can be delivered.</span></div>}
              </div>}
              {!!social.outgoing.length && <div className="pending-list"><strong>Pending invitations</strong>{social.outgoing.map((invitation) => <span key={invitation.id}>{invitation.person.displayName} · waiting</span>)}</div>}
              {!!social.blocked.length && <div className="blocked-list"><strong>Blocked accounts</strong>{social.blocked.map((person) => <div key={person.id}><span>{person.displayName}</span><button onClick={() => void setBlocked(person.id, false)}>Unblock</button></div>)}</div>}
            </section>
            <button className="sign-out-link" type="button" onClick={() => void fetch("/api/auth/logout", { method: "POST" }).then(() => { window.location.href = "/"; })}>Sign out of Whisper</button>
            <nav className="account-legal-links" aria-label="Legal"><a href="/security">Security status</a><a href="/privacy">Privacy Policy</a><a href="/terms">Terms of Service</a></nav>
          </section>
        </div>
      )}

      {reportTarget && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && setReportTarget(null)}>
          <section className="new-chat-modal report-modal" role="dialog" aria-modal="true" aria-labelledby="report-title">
            <button className="modal-close" onClick={() => setReportTarget(null)} aria-label="Close report">×</button>
            <span className="modal-icon danger-icon">!</span><h2 id="report-title">Report {reportTarget.name}</h2><p>Reports are stored for moderation review. Message plaintext is not attached automatically.</p>
            <form onSubmit={submitReport}><label htmlFor="report-category">Reason</label><select id="report-category" value={reportCategory} onChange={(event) => setReportCategory(event.target.value)}><option value="spam">Spam</option><option value="harassment">Harassment</option><option value="impersonation">Impersonation</option><option value="illegal">Illegal content</option><option value="other">Other</option></select><label htmlFor="report-details">Additional details (optional)</label><textarea id="report-details" maxLength={1000} value={reportDetails} onChange={(event) => setReportDetails(event.target.value)} placeholder="Describe what happened without including sensitive information." /><div className="modal-actions"><button type="button" onClick={() => setReportTarget(null)}>Cancel</button><button className="danger-action" type="submit" disabled={socialAction}>Submit report</button></div></form>
          </section>
        </div>
      )}

      {deleteTarget && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && setDeleteTarget(null)}>
          <section className="new-chat-modal confirm-modal" role="dialog" aria-modal="true" aria-labelledby="delete-message-title">
            <span className="modal-icon danger-icon">!</span>
            <h2 id="delete-message-title">Delete this message?</h2>
            <p>It will be replaced by a deleted-message marker after encrypted synchronization.</p>
            <div className="modal-actions">
              <button type="button" onClick={() => setDeleteTarget(null)}>Cancel</button>
              <button className="danger-action" type="button" onClick={() => deleteMessage(deleteTarget)}>Delete message</button>
            </div>
          </section>
        </div>
      )}

      {showShortcutHelp && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && setShowShortcutHelp(false)}>
          <section className="new-chat-modal shortcut-modal" role="dialog" aria-modal="true" aria-labelledby="shortcut-title">
            <button className="modal-close" onClick={() => setShowShortcutHelp(false)} aria-label="Close keyboard shortcuts">×</button>
            <span className="modal-icon">⌨</span>
            <h2 id="shortcut-title">Keyboard shortcuts</h2>
            <div className="shortcut-list">
              <div><span>Search conversations</span><kbd>⌘ K</kbd></div>
              <div><span>Search this chat</span><kbd>⌘ F</kbd></div>
              <div><span>Show shortcuts</span><kbd>⌘ /</kbd></div>
              <div><span>Close panels</span><kbd>Esc</kbd></div>
            </div>
          </section>
        </div>
      )}

      {notice && <div className="toast" role="status">{notice}</div>}
    </main>
  );
}
