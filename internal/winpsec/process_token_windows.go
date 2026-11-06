package winpsec

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const tokenIsAppContainer = 29

func tokenUint32(token windows.Token, class uint32) (uint32, error) {
	var value, size uint32
	if err := windows.GetTokenInformation(token, class, (*byte)(unsafe.Pointer(&value)),
		uint32(unsafe.Sizeof(value)), &size); err != nil {
		return 0, fmt.Errorf("GetTokenInformation(%d): %w", class, err)
	}
	if size != uint32(unsafe.Sizeof(value)) {
		return 0, fmt.Errorf("GetTokenInformation(%d): unexpected size %d", class, size)
	}
	return value, nil
}

func tokenIntegrity(token windows.Token) (*windows.SID, error) {
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("GetTokenInformation(integrity size): %v", err)
	}
	if size < uint32(unsafe.Sizeof(windows.Tokenmandatorylabel{})) {
		return nil, errors.New("truncated token integrity label")
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buffer[0], size, &size); err != nil {
		return nil, fmt.Errorf("GetTokenInformation(integrity): %w", err)
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buffer[0]))
	if label.Label.Sid == nil || !label.Label.Sid.IsValid() {
		return nil, errors.New("invalid token integrity SID")
	}
	sid, err := label.Label.Sid.Copy()
	runtime.KeepAlive(buffer)
	return sid, err
}

// verifyNormalToken never changes privileges, ACLs or integrity labels. In
// particular, do not use IsElevated's bool-only API: query failure must reject.
func verifyNormalToken(token windows.Token) (*windows.SID, error) {
	elevated, err := tokenUint32(token, windows.TokenElevation)
	if err != nil {
		return nil, err
	}
	if elevated != 0 {
		return nil, errors.New("elevated tokens are unsupported; run landcage as a normal user")
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("GetTokenUser: %w", err)
	}
	if user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) ||
		user.User.Sid.IsWellKnown(windows.WinLocalServiceSid) ||
		user.User.Sid.IsWellKnown(windows.WinNetworkServiceSid) {
		return nil, errors.New("Windows service identities are not a normal-user security baseline")
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return nil, fmt.Errorf("GetTokenGroups: %w", err)
	}
	for _, group := range groups.AllGroups() {
		if group.Attributes&windows.SE_GROUP_ENABLED != 0 &&
			(group.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || group.Sid.IsWellKnown(windows.WinLocalSystemSid)) {
			return nil, errors.New("token has an enabled Administrators or SYSTEM SID")
		}
	}
	return user.User.Sid.Copy()
}

func verifyCaller() (_ *windows.SID, err error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil, fmt.Errorf("open caller token: %w", err)
	}
	defer func() { err = errors.Join(err, token.Close()) }()
	user, err := verifyNormalToken(token)
	if err != nil {
		return nil, fmt.Errorf("native PSEC caller: %w", err)
	}
	integrity, err := tokenIntegrity(token)
	if err != nil {
		return nil, err
	}
	// A high-integrity caller without the UAC elevation flag is still not the
	// normal-user baseline. Require medium (not medium-plus) exactly.
	if !integrity.IsWellKnown(windows.WinMediumLabelSid) {
		return nil, errors.New("native PSEC requires a normal medium-integrity caller")
	}
	return user, nil
}

func verifyChildToken(process windows.Handle, expectedUser *windows.SID) (err error) {
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer func() { err = errors.Join(err, token.Close()) }()
	user, err := verifyNormalToken(token)
	if err != nil {
		return err
	}
	if !user.Equals(expectedUser) {
		return errors.New("native PSEC child changed the normal-user identity")
	}
	appContainer, err := tokenUint32(token, tokenIsAppContainer)
	if err != nil {
		return err
	}
	if appContainer != 1 {
		return errors.New("native PSEC child is not an AppContainer")
	}
	integrity, err := tokenIntegrity(token)
	if err != nil {
		return err
	}
	if !integrity.IsWellKnown(windows.WinLowLabelSid) {
		return errors.New("native PSEC child does not have low integrity")
	}
	// AppContainer is the native PSEC-compatible restricted token model.
	// Traditional IsTokenRestricted/RestrictedSids describe a different token
	// mechanism and are not required of a native PSEC AppContainer token.
	return nil
}
