{*******************************************************}
{                                                       }
{                Windows Firewall example               }
{                                                       }
{               Copyright  ©  2014                      }
{                                                       }
{           Journeyman Consultancy & Services           }
{                                                       }
{*******************************************************}
{$WARN GARBAGE OFF}
unit System.Win.Firewall;

interface
uses NetFwTypeLib_TLB, System.Classes, Winapi.ActiveX, System.Generics.Collections;

type
  {$M+}
  TWindowsFirewall = class
  public type
    TWindowsFirewallRule = class
    protected
      FRule: INetFwRule;
      constructor CreateEmptyRule;
    public type
      TWindowsFirewallRuleAction = (Block, Allow);
      TWindowsFirewallRuleActionHelper = record helper for TWindowsFirewallRuleAction
        function ToString: string;
      end;
      TWindowsFirewallRuleDirection = (&In, &Out, Both);
      TWindowsFirewallRuleDirectionHelper = record helper for TWindowsFirewallRuleDirection
        function ToString: string;
      end;
      TWindowsFirewallProfile = (PUBLIC, PRIVATE, DOMAIN, ALL);
      TWindowsFirewallProfileHelper = record helper for TWindowsFirewallProfile
        function ToString: string;
      end;
      TWindowsFirewallProfiles = set of TWindowsFirewallProfile;
      TWindowsFirewallProfilesHelper = record helper for TWindowsFirewallProfiles
        function ToString: string;
      end;
      TWindowsFirewallRuleProtocol = (TCP, UDP, ANY);
      TWindowsFirewallRuleProtocolHelper = record helper for TWindowsFirewallRuleProtocol
        function ToString: string;
      end;
      TWindowsFirewallRuleInterfaceType = (LAN, Wireless, RemoteAccess);
      TWindowsFirewallRuleInterfaceTypeHelper = record helper for TWindowsFirewallRuleInterfaceType
        function ToString: string;
      end;
      TWindowsFirewallRuleInterfaceTypes = set of TWindowsFirewallRuleInterfaceType;
      TWindowsFirewallRuleInterfaceTypesHelper = record helper for TWindowsFirewallRuleInterfaceTypes
        function ToString: string;
      end;
    private
      function getAction: TWindowsFirewallRuleAction;
      procedure setAction(const Value: TWindowsFirewallRuleAction);
      function getApplicationName: string;
      procedure setApplicationName(const Value: string);
      function getDescription: string;
      procedure setDescription(const Value: string);
      function getDirection: TWindowsFirewallRuleDirection;
      procedure setDirection(const Value: TWindowsFirewallRuleDirection);
      function getEdgeTraversal: Boolean;
      procedure setEdgeTraversal(const Value: Boolean);
      function getEnabled: Boolean;
      procedure setEnabled(const Value: Boolean);
      function getGrouping: string;
      procedure setGrouping(const Value: string);
      function getIcmpTypesAndCodes: string;
      procedure setIcmpTypesAndCodes(const Value: string);
      function getInterfaces: TArray<string>;
      procedure setInterfaces(const Values: TArray<string>);
      function getInterfaceTypes: TWindowsFirewallRuleInterfaceTypes;
      procedure setInterfaceTypes(const Values: TWindowsFirewallRuleInterfaceTypes);
      function getLocalAddresses: string;
      procedure setLocalAddresses(const Value: string);
      function getLocalPorts: string;
      procedure setLocalPorts(const Value: string);
      function getName: string;
      procedure setName(const Value: string);
      function getProfile: TWindowsFirewallProfiles;
      procedure setProfile(const Values: TWindowsFirewallProfiles);
      function getProtocol: TWindowsFirewallRuleProtocol;
      procedure setProtocol(const Value: TWindowsFirewallRuleProtocol);
      function getRemoteAddresses: string;
      procedure setRemoteAddresses(const Value: string);
      function getRemotePorts: string;
      procedure setRemotePorts(const Value: string);
      function getServiceName: string;
      procedure setServiceName(const Value: string);
    public
      constructor Create;
      procedure AddIP(const IP: string);
      procedure AddIPs(const SL: TStringList); overload;
      procedure AddIPs(const IPs: TArray<string>); overload;
      destructor Destroy; override;
      property Action: TWindowsFirewallRuleAction read getAction write setAction;
      property ApplicationName: string read getApplicationName write setApplicationName;
      property EdgeTraversal: Boolean read getEdgeTraversal write setEdgeTraversal;
      property Enabled: Boolean read getEnabled write setEnabled;
      property Description: string read getDescription write setDescription;
      property Direction: TWindowsFirewallRuleDirection read getDirection write setDirection;
      property Grouping: string read getGrouping write setGrouping;
      property IcmpTypesAndCodes: string read getIcmpTypesAndCodes write setIcmpTypesAndCodes;
      property Interfaces: TArray<string> read getInterfaces write setInterfaces;
      property InterfaceTypes: TWindowsFirewallRuleInterfaceTypes read getInterfaceTypes write setInterfaceTypes;
      property LocalAddresses: string read getLocalAddresses write setLocalAddresses;
      property LocalPorts: string read getLocalPorts write setLocalPorts;
      property Name: string read getName write setName;
      property Profile: TWindowsFirewallProfiles read getProfile write setProfile;
      property Protocol: TWindowsFirewallRuleProtocol read getProtocol write setProtocol;
      property RemoteAddresses: string read getRemoteAddresses write setRemoteAddresses;
      property RemotePorts: string read getRemotePorts write setRemotePorts;
      property ServiceName: string read getServiceName write setServiceName;
    end;

    TWindowsFirewallRules = class
    protected
      FPolicy: INetFwPolicy2;
      FRules: INetFwRules;
      FRuleList: TObjectList<TWindowsFirewallRule>;
      procedure EnsureRulesExist;
      function getCount: Integer;
      function getRule(const AName: string): TWindowsFirewallRule;
    type
      TFirewallRuleEnumerator = class
      protected
        FRules: INetFwRules;
        FIndex, FCount: Integer;
        FVar: OleVariant;
        FFetched: Cardinal;
        FEnumVARIANT: IEnumVARIANT;
        FRuleList: TObjectList<TWindowsFirewallRule>;
        procedure EnsureCount;
        constructor Create(const ARules: INetFwRules);
        function getCurrent: TWindowsFirewallRule;
      public
        property Current: TWindowsFirewallRule read getCurrent;
        destructor Destroy; override;
        function MoveNext: Boolean;
      end;
    public
      procedure AddRule(const ARule: TWindowsFirewallRule);
      /// <remarks>The TWindowsFirewallRule created by this method must be freed manually.</remarks>
      function CreateRule: TWindowsFirewallRule;
      /// <param name="AName">Name of rule to find</param>
      /// <remarks>Returns True/False depending on if rule is found</remarks>
      function FindRule(const AName: string): Boolean;
      destructor Destroy; override;
      function GetEnumerator: TFirewallRuleEnumerator;
      procedure RemoveRule(const AName: string);
      property Count: Integer read getCount;
      property Rules[const AName: string]: TWindowsFirewallRule read getRule; default;
    end;
  protected
    FFirewall: INetFwMgr;
    class threadvar FInitialized: Boolean;
    class var FRules: TWindowsFirewallRules;
    class procedure Initialize;
    class function getWindowsFirewallRules: TWindowsFirewallRules; static;
    procedure EnsureFirewallAvailable;
    function getEnabled: Boolean;
    procedure setEnabled(const Value: Boolean);
  public
    constructor Create;
    destructor Destroy; override;
    class function CreateRule: INetFwRule;
    class function CreateAllowingRule: INetFwRule;
    class function CreateBlockingRule: INetFwRule;
    class function CreatePolicy: INetFwPolicy2;
    /// <summary>Allows access to a firewall rule given its name.</summary>
    /// <remarks>Rules returned from here are tracked, and will be freed automatically.</remarks>
    class property Rules: TWindowsFirewallRules read getWindowsFirewallRules;
    /// <summary>Check if the firewall is enabled or not.</summary>
    /// <remarks>Returns if the firewall is enabled.</remarks>
    property Enabled: Boolean read getEnabled write setEnabled;
  end;

implementation
uses System.Win.ComObj, System.SysUtils, System.TypInfo, System.Variants,
  System.SysConst, System.Rtti;

{ TWindowsFirewall }

constructor TWindowsFirewall.Create;
begin
  inherited;
  FInitialized := CoInitialize(nil) = S_OK;
end;

class function TWindowsFirewall.CreateAllowingRule: INetFwRule;
begin
  Result := CreateRule;
  Result.Action := NET_FW_ACTION_ALLOW;
end;

class function TWindowsFirewall.CreateBlockingRule: INetFwRule;
begin
  Result := CreateRule;
  Result.Action := NET_FW_ACTION_BLOCK;
end;

class function TWindowsFirewall.CreatePolicy: INetFwPolicy2;
begin
  Initialize;
  Result := CreateComObject(ProgIDToClassID('HNetCfg.FwPolicy2')) as INetFwPolicy2;
end;

class function TWindowsFirewall.CreateRule: INetFwRule;
begin
  Initialize;
  Result := CreateComObject(ProgIDToClassID('HNetCfg.FWRule')) as INetFwRule;
end;

destructor TWindowsFirewall.Destroy;
begin
  FRules.Free;
  if FInitialized then
    CoUninitialize;
  inherited;
end;

procedure TWindowsFirewall.EnsureFirewallAvailable;
begin
  if not Assigned(FFirewall) then
    FFirewall := CreateComObject(ProgIDToClassID('HNetCfg.FwMgr')) as INetFwMgr;
end;

function TWindowsFirewall.getEnabled: Boolean;
begin
  Result := FFirewall.LocalPolicy.CurrentProfile.FirewallEnabled;
end;

class function TWindowsFirewall.getWindowsFirewallRules: TWindowsFirewallRules;
begin
  if not Assigned(FRules) then
    FRules := TWindowsFirewallRules.Create;
  Result := FRules;
end;

class procedure TWindowsFirewall.Initialize;
begin
  if not FInitialized then
    begin
      CoInitialize(nil);
      FInitialized := True;
    end;
end;

procedure TWindowsFirewall.setEnabled(const Value: Boolean);
begin
  EnsureFirewallAvailable;
  FFirewall.LocalPolicy.CurrentProfile.FirewallEnabled := Value;
end;

{ TWindowsFirewallRule }

procedure TWindowsFirewall.TWindowsFirewallRule.AddIP(const IP: string);
var
  LRemoteAddresses, LPad: string;
begin
  LRemoteAddresses := FRule.RemoteAddresses;
  if (LRemoteAddresses = '') or (LRemoteAddresses = '*') then
    begin
      LPad := '';
      if LRemoteAddresses = '*' then LRemoteAddresses := '';
    end else
      LPad := ',';
  FRule.RemoteAddresses := LRemoteAddresses + LPad + IP + '/255.255.255.255';
end;

procedure TWindowsFirewall.TWindowsFirewallRule.AddIPs(const SL: TStringList);
var
  IP: string;
begin
  for IP in SL do
    AddIP(IP);
end;

procedure TWindowsFirewall.TWindowsFirewallRule.AddIPs(const IPs: TArray<string>);
var
  IP: string;
begin
  for IP in IPs do
    AddIP(IP);
end;

constructor TWindowsFirewall.TWindowsFirewallRule.Create;
begin
  CreateEmptyRule;
  FRule := TWindowsFirewall.CreateRule;
end;

constructor TWindowsFirewall.TWindowsFirewallRule.CreateEmptyRule;
begin
  inherited;
end;

destructor TWindowsFirewall.TWindowsFirewallRule.Destroy;
begin
  FRule := nil;
  inherited;
end;

function TWindowsFirewall.TWindowsFirewallRule.getAction: TWindowsFirewallRuleAction;
begin
  case FRule.Action of
    NET_FW_ACTION_BLOCK: Result := TWindowsFirewallRuleAction.Block;
  else
    Result := TWindowsFirewallRuleAction.Allow;
  end;
end;

function TWindowsFirewall.TWindowsFirewallRule.getApplicationName: string;
begin
  Result := FRule.ApplicationName;
end;

function TWindowsFirewall.TWindowsFirewallRule.getLocalAddresses: string;
begin
  Result := FRule.LocalAddresses;
end;

function TWindowsFirewall.TWindowsFirewallRule.getLocalPorts: string;
begin
  Result := FRule.LocalPorts;
end;

function TWindowsFirewall.TWindowsFirewallRule.getDescription: string;
begin
  Result := FRule.Description;
end;

function TWindowsFirewall.TWindowsFirewallRule.getDirection: TWindowsFirewallRuleDirection;
begin
  case FRule.Direction of
    NET_FW_RULE_DIR_IN: Result := &In;
  else
    Result := Out;
  end;
end;

function TWindowsFirewall.TWindowsFirewallRule.getEdgeTraversal: Boolean;
begin
  Result := FRule.EdgeTraversal;
end;

function TWindowsFirewall.TWindowsFirewallRule.getEnabled: Boolean;
begin
  Result := FRule.Enabled;
end;

function TWindowsFirewall.TWindowsFirewallRule.getGrouping: string;
begin
  Result := FRule.Grouping;
end;

function TWindowsFirewall.TWindowsFirewallRule.getIcmpTypesAndCodes: string;
begin
  Result := FRule.IcmpTypesAndCodes;
end;

function TWindowsFirewall.TWindowsFirewallRule.getInterfaces: TArray<string>;
var
  V: Variant;
  P: Pointer;
  Count: Integer;
begin
  V := FRule.Interfaces;
  Result := nil;
  if not VarIsArray(V) or (VarType(V) and varTypeMask <> varString) or
    (VarArrayDimCount(V) <> 1) then
    Exit;

  Count := VarArrayHighBound(V, 1) - VarArrayLowBound(V, 1) + 1;
  if Count = 0 then
    Exit;

  P := VarArrayLock(V);
  try
    SetLength(Result, Count);
    Move(P^, Result[0], Count * SizeOf(Double));
  finally
    VarArrayUnlock(V);
  end;
end;

function TWindowsFirewall.TWindowsFirewallRule.getInterfaceTypes: TWindowsFirewallRuleInterfaceTypes;
var
  LTypes: string;
begin
  Result := [];
  LTypes := UpperCase(FRule.InterfaceTypes);
  if (Pos('LAN', LTypes)<>0) or (Pos('ALL', LTypes)<>0) then
    Result := Result + [LAN];
  if (Pos('WIRELESS', LTypes)<>0) or (Pos('ALL', LTypes)<>0)  then
    Result := Result + [Wireless];
  if (Pos('REMOTEACCESS', LTypes)<>0) or (Pos('ALL', LTypes)<>0)  then
    Result := Result + [RemoteAccess];
end;

function TWindowsFirewall.TWindowsFirewallRule.getName: string;
begin
  Result := FRule.Name;
end;

function TWindowsFirewall.TWindowsFirewallRule.getProfile: TWindowsFirewallProfiles;
const
  cProfile: array[TWindowsFirewallProfile] of TOleEnum = (
    NET_FW_PROFILE2_DOMAIN,
    NET_FW_PROFILE2_PRIVATE,
    NET_FW_PROFILE2_PUBLIC,
    NET_FW_PROFILE2_ALL
  );
type
  TType = (X, Y, Z);
  TTypes = set of TType;
var
  LProfile: TWindowsFirewallProfile;
  LProfiles: Integer;
begin
  Result := [];
  LProfiles := FRule.Profiles;
  for LProfile in [Low(TWindowsFirewallProfile)..High(TWindowsFirewallProfile)] do
    begin
      case LProfiles and cProfile[LProfile] of
        NET_FW_PROFILE2_DOMAIN:  Result := Result + [DOMAIN];
        NET_FW_PROFILE2_PRIVATE: Result := Result + [&PRIVATE];
        NET_FW_PROFILE2_PUBLIC:  Result := Result + [&PUBLIC];
      else
        Result := [DOMAIN, &PRIVATE, &PUBLIC, ALL];
        Break;
      end;
    end;
end;

function TWindowsFirewall.TWindowsFirewallRule.getProtocol: TWindowsFirewallRuleProtocol;
begin
  case FRule.Protocol of
    NET_FW_IP_PROTOCOL_TCP: Result := TCP;
    NET_FW_IP_PROTOCOL_UDP: Result := UDP;
  else
    Result := ANY;
  end;
end;

function TWindowsFirewall.TWindowsFirewallRule.getRemoteAddresses: string;
begin
  Result := FRule.RemoteAddresses;
end;

function TWindowsFirewall.TWindowsFirewallRule.getRemotePorts: string;
begin
  Result := FRule.RemotePorts;
end;

function TWindowsFirewall.TWindowsFirewallRule.getServiceName: string;
begin
  Result := FRule.serviceName;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setAction(
  const Value: TWindowsFirewallRuleAction);
const
  cAction: array[TWindowsFirewallRuleAction] of TOleEnum = (
    NET_FW_ACTION_BLOCK, NET_FW_ACTION_ALLOW
  );
begin
  FRule.Action := cAction[Value];
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setApplicationName(
  const Value: string);
begin
  FRule.ApplicationName := Value;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setLocalAddresses(
  const Value: string);
begin
  FRule.LocalAddresses := Value;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setLocalPorts(
  const Value: string);
begin
  FRule.LocalPorts := Value;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setDescription(
  const Value: string);
begin
  FRule.Description := Value;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setDirection(
  const Value: TWindowsFirewallRuleDirection);
const
  cDirection: array[TWindowsFirewallRuleDirection] of TOleEnum = (
    NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT, NET_FW_RULE_DIR_MAX
  );
begin
  FRule.Direction := cDirection[Value];
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setEdgeTraversal(
  const Value: Boolean);
begin
  FRule.EdgeTraversal := Value;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setEnabled(
  const Value: Boolean);
begin
  FRule.Enabled := Value;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setGrouping(
  const Value: string);
begin
  FRule.Grouping := Value;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setIcmpTypesAndCodes(
  const Value: string);
begin
  FRule.IcmpTypesAndCodes := Value;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setInterfaces(
  const Values: TArray<string>);
var
  LVariant: Variant;
begin
  LVariant := Values;
  FRule.Interfaces := LVariant;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setInterfaceTypes(
  const Values: TWindowsFirewallRuleInterfaceTypes);
var
  LTypes: string;
  LType: TWindowsFirewallRuleInterfaceType;
const
  cType: array[TWindowsFirewallRuleInterfaceType] of string = (
    'Lan', 'Wireless', 'RemoteAccess'
  );
begin
  LTypes := '';
  for LType in Values do
    begin
      if LTypes = '' then
        LTypes := cType[LType] else
        LTypes := LTypes + ',' + cType[LType];
    end;
  FRule.InterfaceTypes := LTypes;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setName(const Value: string);
begin
  FRule.Name := Value;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setProfile(
  const Values: TWindowsFirewallProfiles);
const
  cProfile: array[TWindowsFirewallProfile] of TOleEnum = (
    NET_FW_PROFILE2_DOMAIN,
    NET_FW_PROFILE2_PRIVATE,
    NET_FW_PROFILE2_PUBLIC,
    NET_FW_PROFILE2_ALL
  );
var
  LProfile: TWindowsFirewallProfile;
  LProfiles: TOleEnum;
begin
  //  FRule.Profiles := cProfile[Value];
  LProfiles := 0;
  for LProfile in [Low(TWindowsFirewallProfile)..High(TWindowsFirewallProfile)] do
    if LProfile in Values then
      LProfiles := LProfiles or cProfile[LProfile];
  FRule.Profiles := LProfiles;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setProtocol(
  const Value: TWindowsFirewallRuleProtocol);
const
  cProtocol: array[TWindowsFirewallRuleProtocol] of TOleEnum = (
    NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP, NET_FW_IP_PROTOCOL_ANY);
begin
  FRule.Protocol := cProtocol[Value];
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setRemoteAddresses(
  const Value: string);
begin
  FRule.RemoteAddresses := Value;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setRemotePorts(
  const Value: string);
begin
  FRule.RemotePorts := Value;
end;

procedure TWindowsFirewall.TWindowsFirewallRule.setServiceName(
  const Value: string);
begin
  FRule.serviceName := Value;
end;

{ TWindowsFirewallRules }

procedure TWindowsFirewall.TWindowsFirewallRules.AddRule(
  const ARule: TWindowsFirewallRule);
begin
  EnsureRulesExist;
  FRules.Add(ARule.FRule);
end;

function TWindowsFirewall.TWindowsFirewallRules.CreateRule: TWindowsFirewallRule;
begin
  EnsureRulesExist;
  Result := TWindowsFirewallRule.Create;
end;

destructor TWindowsFirewall.TWindowsFirewallRules.Destroy;
begin
  FRuleList.Free;
  FRules  := nil;
  FPolicy := nil;
  inherited;
end;

procedure TWindowsFirewall.TWindowsFirewallRules.EnsureRulesExist;
var
  LClassID: string;
  LGUID: TGUID;
begin
  if not Assigned(FPolicy) then
    begin
      LGUID := ProgIDToClassID('HNetCfg.FwPolicy2');
      LClassID := LGUID.ToString;
      FPolicy := CreateComObject(LGUID) as INetFwPolicy2;
      FRules := FPolicy.Rules;
    end;
end;

function TWindowsFirewall.TWindowsFirewallRules.FindRule(const AName: string): Boolean;
begin
  EnsureRulesExist;
  try
    Result := Assigned(FRules.Item(AName));
  except
    on E: EOleException do
      Result := False;
  end;
end;

function TWindowsFirewall.TWindowsFirewallRules.getCount: Integer;
begin
  EnsureRulesExist;
  Result := FRules.Count;
end;

function TWindowsFirewall.TWindowsFirewallRules.GetEnumerator: TFirewallRuleEnumerator;
begin
  EnsureRulesExist;
  Result := TFirewallRuleEnumerator.Create(FRules);
end;

function TWindowsFirewall.TWindowsFirewallRules.getRule(
  const AName: string): TWindowsFirewallRule;
var
  LRule: INetFwRule;
begin
  EnsureRulesExist;
  LRule := FRules.Item(AName);
  Result := TWindowsFirewall.TWindowsFirewallRule.CreateEmptyRule;
  Result.FRule := LRule;
end;

procedure TWindowsFirewall.TWindowsFirewallRules.RemoveRule(
  const AName: string);
begin
  EnsureRulesExist;
  FRules.Remove(AName);
end;

{ TWindowsFirewall.TWindowsFirewallRules.TFirewallRuleEnumerator }

constructor TWindowsFirewall.TWindowsFirewallRules.TFirewallRuleEnumerator.Create(
  const ARules: INetFwRules);
begin
  inherited Create;
  FRules := ARules;
  VarClear(FVar);
  FCount := -1;
  Supports(FRules._NewEnum, IEnumVARIANT, FEnumVARIANT);
  FRuleList := TObjectList<TWindowsFirewallRule>.Create;
end;

destructor TWindowsFirewall.TWindowsFirewallRules.TFirewallRuleEnumerator.Destroy;
begin
  FRuleList.Free;
  FEnumVARIANT := nil;
  FRules := nil;
  inherited;
end;

procedure TWindowsFirewall.TWindowsFirewallRules.TFirewallRuleEnumerator.EnsureCount;
begin
  if FCount = -1 then
    FCount := FRules.Count;
end;

function TWindowsFirewall.TWindowsFirewallRules.TFirewallRuleEnumerator.getCurrent: TWindowsFirewallRule;
var
  LRule: INetFwRule;
begin
  Result := TWindowsFirewallRule.CreateEmptyRule;
  FRuleList.Add(Result);
  if FEnumVARIANT.Next(1, FVar, FFetched) = S_OK then
    begin
      Supports(FVar, INetFwRule, LRule);
      Result.FRule := LRule;
      if Pos('File Transfer', Result.Name)<>0 then
        asm nop end;
    end;
end;

function TWindowsFirewall.TWindowsFirewallRules.TFirewallRuleEnumerator.MoveNext: Boolean;
begin
  EnsureCount;
  Result := FIndex < FCount;
  if Result then
    Inc(FIndex);
end;

{ TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleProtocolHelper }

function TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleProtocolHelper.ToString: string;
begin
  Result := GetEnumName(TypeInfo(TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleProtocol), Ord(Self));
end;

{ TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleActionHelper }

function TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleActionHelper.ToString: string;
begin
  Result := GetEnumName(TypeInfo(TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleAction), Ord(Self));
end;

{ TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallProfileHelper }

function TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallProfileHelper.ToString: string;
begin
  Result := GetEnumName(TypeInfo(TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallProfile), Ord(Self));
end;

function TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallProfilesHelper.ToString: string;
var
  LType: TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallProfile;
  LSet: string;
begin
  LSet := '';
  for LType in Self do
    if LSet = '' then
      LSet := LType.ToString else
      LSet := LSet + ',' + LType.ToString;
  Result := '[' + LSet + ']';
end;

{ TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleDirectionHelper }

function TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleDirectionHelper.ToString: string;
begin
  Result := GetEnumName(TypeInfo(TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleDirection), Ord(Self));
end;

{ TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleInterfaceTypesHelper }

function TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleInterfaceTypeHelper.ToString: string;
begin
  Result := GetEnumName(TypeInfo(TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleInterfaceType), Ord(Self));
end;

{ TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleInterfaceTypesHelper }

function TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleInterfaceTypesHelper.ToString: string;
var
  LType: TWindowsFirewall.TWindowsFirewallRule.TWindowsFirewallRuleInterfaceType;
  LSet: string;
begin
  LSet := '';
  for LType in Self do
    if LSet = '' then
      LSet := LType.ToString else
      LSet := LSet + ',' + LType.ToString;
  Result := '[' + LSet + ']';
end;

end.



























































{*******************************************************}
{                                                       }
{                  Windows Firewall example             }
{                                                       }
{           Journeyman Consultancy & Services           }
{                                                       }
{*******************************************************}

